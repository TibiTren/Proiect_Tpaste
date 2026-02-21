use argon2::{Argon2, PasswordHasher};
use axum::extract::Query;
use axum::{
    extract::{Form, Path, State},
    response::Html,
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::SameSite;
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Utc};
use password_hash::{rand_core::OsRng, PasswordHash, PasswordVerifier, SaltString};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_cookies::CookieManagerLayer;
use tower_cookies::{Cookie, Cookies};
use uuid::Uuid;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Paste {
    id: String,
    text: String,
    created_at: DateTime<Utc>,
}

type Store = Arc<Mutex<HashMap<String, Vec<Paste>>>>;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct User {
    password: String,
}

#[derive(Clone)]
struct TokenInfo {
    username: String,
    expires_at: i64,
}

type Users = Arc<Mutex<HashMap<String, User>>>;
type Tokens = Arc<Mutex<HashMap<String, TokenInfo>>>;
#[derive(Clone)]
struct AppState {
    store: Store,
    users: Users,
    tokens: Tokens,
}

#[derive(Deserialize)]
struct PasteForm {
    text: String,
}

#[derive(Deserialize)]
struct AuthForm {
    username: String,
    password: String,
}

fn load_users() -> HashMap<String, User> {
    if let Ok(text) = std::fs::read_to_string("users.json") {
        if let Ok(map) = serde_json::from_str::<HashMap<String, User>>(&text) {
            return map;
        }
    }
    HashMap::new()
}

fn save_users(map: &HashMap<String, User>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write("users.json", json);
    }
}

fn load_pastes() -> HashMap<String, Vec<Paste>> {
    if let Ok(text) = std::fs::read_to_string("pastes.json") {
        if let Ok(map) = serde_json::from_str::<HashMap<String, Vec<Paste>>>(&text) {
            return map;
        }
    }
    HashMap::new()
}

fn save_pastes(map: &HashMap<String, Vec<Paste>>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        let _ = std::fs::write("pastes.json", json);
    }
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    match Argon2::default().hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(_) => "".to_string(),
    }
}

fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<AuthForm>,
) -> (CookieJar, Html<String>) {
    let mut users = match state.users.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut tokens = match state.tokens.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if users.contains_key(&form.username) {
        return (jar, Html("User already exists".into()));
    }

    users.insert(
        form.username.clone(),
        User {
            password: hash_password(&form.password),
        },
    );
    save_users(&users);

    let token = Uuid::new_v4().to_string();
    let expires = (Utc::now() + chrono::Duration::days(60)).timestamp();

    tokens.insert(
        token.clone(),
        TokenInfo {
            username: form.username.clone(),
            expires_at: expires,
        },
    );

    let mut cookie = Cookie::new("auth_token", token);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::days(60));

    let jar = jar.add(cookie);
    (jar, Html("Logged in".into()))
}

async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<AuthForm>,
) -> Html<String> {
    let users = match state.users.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut tokens = match state.tokens.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    match users.get(&form.username) {
        Some(u) if verify_password(&form.password, &u.password) => {
            let token = Uuid::new_v4().to_string();
            let expires = (Utc::now() + chrono::Duration::days(60)).timestamp();

            tokens.insert(
                token.clone(),
                TokenInfo {
                    username: form.username.clone(),
                    expires_at: expires,
                },
            );

            let mut cookie = Cookie::new("auth_token", token);
            cookie.set_path("/");
            cookie.set_http_only(true);

            cookies.add(cookie);

            Html("Logged in".into())
        }
        _ => Html("Invalid credentials".into()),
    }
}

async fn create_paste(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<PasteForm>,
) -> Html<String> {
    let Some(cookie) = cookies.get("auth_token") else {
        return Html("Nu ești autentificat".into());
    };

    let token = cookie.value();

    let tokens = match state.tokens.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(info) = tokens.get(token) else {
        return Html("Token invalid".into());
    };

    if info.expires_at < Utc::now().timestamp() {
        return Html("Token expirat".into());
    }
    let username = info.username.clone();
    drop(tokens);
    let id = Uuid::new_v4().to_string();
    let paste = Paste {
        id: id.clone(),
        text: form.text,
        created_at: Utc::now(),
    };

    let mut store = match state.store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let entry = store.entry(username.clone()).or_default();
    entry.push(paste);
    save_pastes(&store);
    Html(format!(
    "Link: http://localhost:3000/paste/{id}\nPagina user: http://localhost:3000/user?id={username}"
))
}

async fn show_paste(State(state): State<AppState>, Path(id): Path<String>) -> Html<String> {
    let store = match state.store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    for (_user, pastes) in store.iter() {
        if let Some(p) = pastes.iter().find(|p| p.id == id) {
            return Html(format!(
                "<h1>Paste</h1>\
                 <p>Created at: {}</p>\
                 <pre>{}</pre>",
                p.created_at, p.text
            ));
        }
    }

    Html("<h2>Paste inexistent</h2>".into())
}

async fn show_user_pastes(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Html<String> {
    let username = match params.get("id") {
        Some(u) => u,
        None => return Html("Missing id".into()),
    };

    let store = match state.store.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    if let Some(pastes) = store.get(username.as_str()) {
        let mut body = String::new();
        body.push_str(&format!("<h1>Paste-urile lui {}</h1><ul>", username));

        for p in pastes {
            body.push_str(&format!(
                "<li>\
                   <a href=\"/paste/{}\">{}</a> \
                   – {}\
                 </li>",
                p.id, p.id, p.created_at,
            ));
        }

        body.push_str("</ul>");
        Html(body)
    } else {
        Html(format!(
            "<h2>Utilizatorul {} nu are paste-uri (sau nu există)</h2>",
            username
        ))
    }
}

pub async fn run() {
    let state = AppState {
        store: Arc::new(Mutex::new(load_pastes())),
        users: Arc::new(Mutex::new(load_users())),
        tokens: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/paste/:id", get(show_paste))
        .route("/user", get(show_user_pastes))
        .route(
            "/paste",
            get(|| async {
                Html(
                    r#"
                <h1>Adaugă un paste</h1>
                <form method="POST" action="/paste">
                    <textarea name="text" rows="10" cols="60"></textarea><br>
                    <button type="submit">Trimite</button>
                </form>
            "#,
                )
            })
            .post(create_paste),
        )
        .layer(CookieManagerLayer::new())
        .with_state(state);

    println!("Server pornit pe http://localhost:3000");

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        Ok(l) => l,

        Err(e) => {
            eprintln!("Eroare la bind pe portul 3000: {}", e);
            return;
        }
    };

    match axum::serve(listener, app.into_make_service()).await {
        Ok(_) => (),
        Err(e) => eprintln!("Eroare la rularea serverului: {}", e),
    }
}
