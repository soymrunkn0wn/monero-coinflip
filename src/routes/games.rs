use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};

use futures::TryStreamExt;
use mongodb::bson::{DateTime, Decimal128, oid::ObjectId};
use mongodb::{Collection, options::FindOptions};
use rand::{Rng, rngs::OsRng};
use rust_decimal::{Decimal, prelude::*};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::AppState;
use crate::middlewares::auth::UserId;
use crate::models::{AdminBalance, Game, User};

const MIN_WAGER: f64 = 0.001; // Minimum wager amount = $0.40
const PLATFORM_FEE_RATE: f64 = 0.01; // Platform takes 1% fee

#[derive(Deserialize)]
struct CreateGameRequest {
    wager: String, // String to parse to Decimal128
}

async fn create_game(
    State(state): State<AppState>,
    user_id: UserId,
    Json(req): Json<CreateGameRequest>,
) -> Response {
    let db = &state.db;
    let users: Collection<User> = db.collection("users");
    let games: Collection<Game> = db.collection("games");

    let wager_decimal = match Decimal::from_str(&req.wager) {
        Ok(d) if d.to_f64().unwrap_or(0.0) >= MIN_WAGER => d,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid or too small wager".to_string(),
            )
                .into_response();
        }
    };
    let wager = Decimal128::from_str(&wager_decimal.to_string()).unwrap();

    // Find user and check balance
    let user_id_obj = match ObjectId::parse_str(&user_id.0) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid user ID".to_string()).into_response(),
    };
    let mut user = match users
        .find_one(mongodb::bson::doc! { "_id": user_id_obj }, None)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found".to_string()).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
    };

    // Simulate balance check (TODO: Monitor on-chain deposits)
    // For now, assume balance is sufficient or check DB
    let balance_decimal = Decimal::from_str(&user.balance.to_string()).unwrap();
    if balance_decimal < wager_decimal {
        return (StatusCode::BAD_REQUEST, "Insufficient balance".to_string()).into_response();
    }

    // Deduct balance and update DB
    let new_balance = balance_decimal - wager_decimal;
    user.balance = Decimal128::from_str(&new_balance.to_string()).unwrap();
    if let Err(e) = users
        .replace_one(mongodb::bson::doc! { "_id": user_id_obj }, &user, None)
        .await
    {
        eprintln!("Error updating creator balance: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update creator balance: {}", e),
        )
            .into_response();
    }

    // Simulate transfer from user address to platform (escrow)
    println!(
        "Simulating wager transfer: {} XMR from {} to platform",
        wager_decimal, user.wallet_address
    );
    println!(
        "Creator balance after deduction: {} (deducted {})",
        new_balance, wager_decimal
    );

    // Create game
    let now = DateTime::now();
    let game = Game {
        id: None,
        creator_id: user_id_obj,
        opponent_id: None,
        wager,
        status: "open".to_string(),
        outcome: None,
        winner_id: None,
        platform_fee: None,
        created_at: now,
        updated_at: now,
    };

    let result = match games.insert_one(game, None).await {
        Ok(res) => res,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
    };
    let id = match result.inserted_id.as_object_id() {
        Some(oid) => oid,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get inserted ID".to_string(),
            )
                .into_response();
        }
    };

    (StatusCode::CREATED, Json(id.to_hex())).into_response()
}

#[derive(Serialize, Clone)]
pub struct OpenGame {
    pub id: String,
    pub creator: String, // Simplified, could expand
    pub wager: String,
    pub created_at: DateTime,
}

async fn list_open_games(State(state): State<AppState>) -> impl IntoResponse {
    let db = &state.db;
    let games: Collection<Game> = db.collection("games");

    let filter = mongodb::bson::doc! { "status": "open" };
    let options = FindOptions::builder()
        .sort(mongodb::bson::doc! { "created_at": -1 })
        .build();
    let mut cursor = games.find(filter, options).await.unwrap();

    let mut open_games = Vec::new();
    while let Some(game) = cursor.try_next().await.unwrap() {
        open_games.push(OpenGame {
            id: game.id.unwrap().to_hex(),
            creator: game.creator_id.to_hex(), // Or fetch username if available
            wager: Decimal::from_str(&game.wager.to_string())
                .unwrap()
                .to_string(),
            created_at: game.created_at,
        });
    }

    Json(open_games)
}

async fn join_game(
    State(state): State<AppState>,
    user_id: UserId,
    Path(game_id): Path<String>,
) -> Response {
    let db = &state.db;
    let users: Collection<User> = db.collection("users");
    let games: Collection<Game> = db.collection("games");
    let platform_address = &state.platform_address;

    let game_id_obj = match ObjectId::parse_str(&game_id) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid game ID".to_string()).into_response(),
    };
    let mut game = match games
        .find_one(mongodb::bson::doc! { "_id": game_id_obj }, None)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => return (StatusCode::NOT_FOUND, "Game not found".to_string()).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
    };

    if game.status != "open" {
        return (StatusCode::BAD_REQUEST, "Game is not open".to_string()).into_response();
    }

    let opponent_id_obj = match ObjectId::parse_str(&user_id.0) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid user ID".to_string()).into_response(),
    };
    if game.creator_id == opponent_id_obj {
        return (
            StatusCode::BAD_REQUEST,
            "Cannot join your own game".to_string(),
        )
            .into_response();
    }

    let wager_decimal = Decimal::from_str(&game.wager.to_string()).unwrap();

    // Find opponent and check balance
    let mut opponent = match users
        .find_one(mongodb::bson::doc! { "_id": opponent_id_obj }, None)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "User not found".to_string()).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
                .into_response();
        }
    };
    // Simulate balance check (TODO: Monitor on-chain deposits)
    // For now, assume balance is sufficient or check DB
    if Decimal::from_str(&opponent.balance.to_string()).unwrap() < wager_decimal {
        return (StatusCode::BAD_REQUEST, "Insufficient balance".to_string()).into_response();
    }

    // Simulate transfer from opponent address to platform (escrow)
    println!(
        "Simulating wager transfer: {} XMR from {} to platform",
        wager_decimal, opponent.wallet_address
    );

    // Deduct opponent balance
    let opponent_balance_decimal: Decimal = opponent.balance.to_string().parse().unwrap();
    let new_opponent_balance = opponent_balance_decimal - wager_decimal;
    opponent.balance = Decimal128::from_str(&new_opponent_balance.to_string()).unwrap();
    if let Err(e) = users
        .replace_one(
            mongodb::bson::doc! { "_id": opponent_id_obj },
            &opponent,
            None,
        )
        .await
    {
        eprintln!("Error updating opponent balance: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update opponent balance: {}", e),
        )
            .into_response();
    }

    // Log balance deductions
    println!(
        "Opponent balance after: {} (deducted {})",
        new_opponent_balance, wager_decimal
    );

    // Update game
    game.opponent_id = Some(opponent_id_obj);
    game.status = "active".to_string();
    if let Err(e) = games
        .replace_one(mongodb::bson::doc! { "_id": game_id_obj }, &game, None)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response();
    }

    // Execute coinflip
    let outcome = if OsRng.gen_bool(0.5) {
        "heads"
    } else {
        "tails"
    }; // heads: creator wins, tails: opponent wins
    let winner_id = if outcome == "heads" {
        game.creator_id
    } else {
        opponent_id_obj
    };

    let total_wager = wager_decimal * Decimal::from(2);
    let fee = total_wager * Decimal::from_f64(PLATFORM_FEE_RATE).unwrap();
    let payout = total_wager - fee;

    // Fetch user addresses for transfers
    let creator_addr = match users
        .find_one(mongodb::bson::doc! { "_id": game.creator_id }, None)
        .await
    {
        Ok(Some(u)) => u.wallet_address,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Creator not found".to_string(),
            )
                .into_response();
        }
    };
    let opponent_addr = match users
        .find_one(mongodb::bson::doc! { "_id": opponent_id_obj }, None)
        .await
    {
        Ok(Some(u)) => u.wallet_address,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Opponent not found".to_string(),
            )
                .into_response();
        }
    };
    let winner_addr = if winner_id == game.creator_id {
        creator_addr
    } else {
        opponent_addr
    };

    // Update winner's DB balance for payout
    let winner_filter = mongodb::bson::doc! { "_id": winner_id };
    let winner_update = mongodb::bson::doc! { "$inc": { "balance": Decimal128::from_str(&payout.to_string()).unwrap() } };
    if let Err(e) = users.update_one(winner_filter, winner_update, None).await {
        eprintln!("Error updating winner balance: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update winner balance: {}", e),
        )
            .into_response();
    }
    println!("Winner payout: {} XMR added to balance", payout);

    // Accumulate fee in admin balance
    let admin_collection = state.db.collection::<AdminBalance>("admin_balance");
    let mut admin_balance = admin_collection
        .find_one(mongodb::bson::doc! {}, None)
        .await
        .unwrap_or_default()
        .unwrap_or_default();
    let fee_decimal = Decimal::from_f64(PLATFORM_FEE_RATE).unwrap() * total_wager;
    let admin_balance_decimal: Decimal = admin_balance.balance.to_string().parse().unwrap();
    admin_balance.balance =
        Decimal128::from_str(&(admin_balance_decimal + fee_decimal).to_string()).unwrap();
    admin_collection
        .replace_one(
            mongodb::bson::doc! { "_id": admin_balance.id },
            &admin_balance,
            None,
        )
        .await
        .unwrap();
    println!(
        "Platform fee accumulated: {} XMR (total admin balance: {})",
        fee_decimal,
        admin_balance_decimal + fee_decimal
    );

    // Update game
    game.status = "completed".to_string();
    game.outcome = Some(outcome.to_string());
    game.winner_id = Some(winner_id);
    game.platform_fee = Some(Decimal128::from_str(&fee.to_string()).unwrap());
    game.updated_at = DateTime::now();
    let _ = games
        .replace_one(mongodb::bson::doc! { "_id": game_id_obj }, &game, None)
        .await;

    (StatusCode::OK, "Game joined and completed".to_string()).into_response()
}

pub fn game_routes() -> Router<AppState> {
    Router::new()
        .route("/games", post(create_game).get(list_open_games))
        .route("/games/:id/join", post(join_game))
}
