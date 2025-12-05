mod db;
mod middlewares;
mod models;
mod routes;
use crate::db::connect_to_mongo;
use crate::middlewares::auth::auth_middleware;

use crate::routes::auth::auth_routes;
use crate::routes::games::game_routes;

use axum::{Router, response::Html, routing::get};
use dioxus::prelude::*;
use dioxus_core::NoOpMutations;
use mongodb::bson::doc;
use mongodb::options::FindOptions;
use mongodb::{Collection, Database};
use rust_decimal::{Decimal, prelude::FromStr};

use crate::models::Game;
use crate::routes::games::OpenGame;
use axum::extract::State;
use futures::TryStreamExt;
use monero_rpc::{RpcClient, WalletClient};
use std::env;
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

fn lobby_app(games: Vec<OpenGame>) -> Element {
    rsx! {
        head {
            title { "Coinflip Lobby" }
            script { src: "https://cdn.tailwindcss.com" }
            script { src: "/assets/htmx.js" }
        }
        body {
            class: "bg-gray-100 p-4",
            div {
                class: "max-w-4xl mx-auto",
                h1 { class: "text-3xl font-bold mb-4", "Open Games" }
                div {
                    id: "games-list",
                    "hx-get": "/games",
                    "hx-trigger": "every 10s",
                    "hx-swap": "innerHTML",
                    for game in games.iter() {
                        div {
                            class: "bg-white p-4 mb-2 rounded shadow",
                            p { "Game ID: {game.id}" }
                            p { "Creator: {game.creator}" }
                            p { "Wager: {game.wager} XMR" }
                            p { "Created: {game.created_at.try_to_rfc3339_string().unwrap_or(\"Invalid Date\".to_string())}" }
                            button {
                                "hx-post": "/games/{game.id}/join",
                                class: "bg-blue-500 text-white px-4 py-2 rounded",
                                "Join Game"
                            }
                        }
                    }
                }
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

async fn lobby(State(state): State<AppState>) -> Html<String> {
    let db = &state.db;
    let games_coll: Collection<Game> = db.collection("games");

    let filter = doc! { "status": "open" };
    let options = FindOptions::builder()
        .sort(doc! { "created_at": -1 })
        .build();
    let mut cursor = games_coll.find(filter, options).await.unwrap();

    let mut open_games = Vec::new();
    while let Some(game) = cursor.try_next().await.unwrap() {
        open_games.push(OpenGame {
            id: game.id.unwrap().to_hex(),
            creator: game.creator_id.to_hex(),
            wager: Decimal::from_str(&game.wager.to_string())
                .unwrap()
                .to_string(),
            created_at: game.created_at,
        });
    }

    let mut renderer = dioxus_ssr::Renderer::new();
    let mut buffer = String::new();
    let mut vdom = VirtualDom::new_with_props(lobby_app, open_games.into());
    let mut mutations = NoOpMutations;
    vdom.rebuild(&mut mutations);
    renderer.render_to(&mut buffer, &vdom).unwrap();
    Html(format!("<!DOCTYPE html><html>{}</html>", buffer))
}

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
    wallet_rpc: Arc<WalletClient>,
    platform_address: String,
}

#[tokio::main]
async fn main() {
    let db = connect_to_mongo()
        .await
        .expect("Failed to connect to MongoDB");
    println!("Successfully connected to MongoDB!");

    let platform_address = env::var("PLATFORM_WALLET_ADDRESS")
        .unwrap_or_else(|_| "4ABC...your_default_platform_address".to_string());
    println!("Platform wallet address for fees: {}", platform_address);

    let rpc_url =
        env::var("MONERO_WALLET_RPC_URL").unwrap_or_else(|_| "http://localhost:18081".to_string());
    println!("Using Monero Wallet RPC URL: {}", rpc_url);
    let client = RpcClient::new(rpc_url).expect("Failed to create RPC client");
    let wallet_rpc = Arc::new(client.wallet());
    let state = AppState {
        db: Arc::new(db),
        wallet_rpc,
        platform_address,
    };

    let protected_api = Router::new()
        .merge(game_routes())
        .layer(axum::middleware::from_fn(auth_middleware));

    let app = Router::new()
        .route("/", get(home))
        .route("/lobby", get(lobby))
        .merge(auth_routes())
        .merge(protected_api)
        .nest_service(
            "/assets",
            axum::routing::get_service(ServeDir::new("assets")),
        )
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
