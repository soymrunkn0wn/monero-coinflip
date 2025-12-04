mod db;
mod models;
mod routes;
use crate::db::connect_to_mongo;
use crate::models::{Game, Transaction, User};
use crate::routes::auth::auth_routes;
use axum::{Router, response::Html, routing::get};
use dioxus::prelude::*;
use dioxus_core::NoOpMutations;
use mongodb::Database;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

fn app() -> Element {
    rsx! {
        head {
            title { "Coinflip Game" }
            script { src: "https://cdn.tailwindcss.com" }
            script { src: "/assets/htmx.js" }
        }
        body {
            class: "bg-gray-100",
            div {
                class: "text-center text-4xl font-bold mt-10",
                "Hello, World!"
            }
        }
    }
}

async fn home() -> Html<String> {
    let mut renderer = dioxus_ssr::Renderer::new();
    let mut buffer = String::new();
    let mut vdom = VirtualDom::new(app);
    let mut mutations = NoOpMutations;
    vdom.rebuild(&mut mutations);
    renderer.render_to(&mut buffer, &vdom).unwrap();
    Html(format!("<!DOCTYPE html><html>{}</html>", buffer))
}

async fn lobby() -> Html<String> {
    let mut renderer = dioxus_ssr::Renderer::new();
    let mut buffer = String::new();
    let mut vdom = VirtualDom::new(app);
    let mut mutations = NoOpMutations;
    vdom.rebuild(&mut mutations);
    renderer.render_to(&mut buffer, &vdom).unwrap();
    Html(format!("<!DOCTYPE html><html>{}</html>", buffer))
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
}

#[tokio::main]
async fn main() {
    let db = connect_to_mongo()
        .await
        .expect("Failed to connect to MongoDB");
    println!("Successfully connected to MongoDB!");

    let state = AppState { db: Arc::new(db) };

    let app = Router::new()
        .route("/", get(home))
        .route("/lobby", get(lobby))
        .nest_service(
            "/assets",
            axum::routing::get_service(ServeDir::new("assets")),
        )
        .merge(auth_routes())
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
