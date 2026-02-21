mod server;
use server::run;

use reqwest::header;
use std::{fs, io::Read};

#[tokio::main]
async fn main() {
    let mut args = std::env::args();
    args.next();

    match args.next().as_deref() {
        Some("Server") => run().await,

        Some("Register") => {
            let username = match args.next() {
                Some(u) => u,
                None => {
                    eprintln!("Lipsește username-ul");
                    return;
                }
            };
            let password = match args.next() {
                Some(p) => p,
                None => {
                    eprintln!("Lipsește parola");
                    return;
                }
            };

            let client = reqwest::Client::new();
            let _ = client
                .post("http://localhost:3000/register")
                .form(&[("username", username), ("password", password)])
                .send()
                .await;
        }

        Some("Login") => {
            let username = match args.next() {
                Some(u) => u,
                None => {
                    eprintln!("Lipsește username-ul");
                    return;
                }
            };
            let password = match args.next() {
                Some(p) => p,
                None => {
                    eprintln!("Lipsește parola");
                    return;
                }
            };

            let client = reqwest::Client::new();

            let resp = match client
                .post("http://localhost:3000/login")
                .form(&[
                    ("username", username.as_str()),
                    ("password", password.as_str()),
                ])
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Eroare la login: {}", e);
                    return;
                }
            };

            let headers = resp.headers().clone();

            if let Some(set_cookie) = headers.get(header::SET_COOKIE) {
                let cookie_str = match set_cookie.to_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        eprintln!("Set-Cookie header conține caractere invalide");
                        return;
                    }
                };
                let filename = format!("cookie_{}.txt", username);
                match fs::write(&filename, cookie_str) {
                    Ok(_) => println!("Cookie salvat în {}", filename),
                    Err(e) => eprintln!("Eroare la salvarea cookie-ului: {}", e),
                };
            } else {
                eprintln!("Serverul nu a trimis Set-Cookie");
            }
        }

        Some("tpaste") => {
            let username = match args.next() {
                Some(u) => u,
                None => {
                    eprintln!("Lipsește username-ul");
                    return;
                }
            };

            let mut content = String::new();
            match std::io::stdin().read_to_string(&mut content) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Eroare la citirea de la stdin: {}", e);
                    return;
                }
            };

            if content.trim().is_empty() {
                eprintln!("Nu ai trimis text.");
                return;
            }

            let filename = format!("cookie_{}.txt", username);
            let cookie_str = match fs::read_to_string(&filename) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Eroare la citirea cookie-ului din {}: {}", filename, e);
                    return;
                }
            };

            let client = reqwest::Client::new();

            let resp = match client
                .post("http://localhost:3000/paste")
                .header(header::COOKIE, cookie_str.trim())
                .form(&[("text", content.as_str())])
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Eroare la trimiterea paste-ului: {}", e);
                    return;
                }
            };
            let body = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("Eroare la citirea răspunsului: {}", e);
                    return;
                }
            };

            println!("{}", body);
        }
        _ => {
            println!("Comenzi:");
            println!("  Server");
            println!("  Register <user> <pass>");
            println!("  Login <user> <pass>");
            println!("  tpaste <user>");
        }
    }
}
