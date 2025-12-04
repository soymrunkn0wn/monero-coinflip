use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use mongodb::Collection;
use mongodb::bson::{DateTime, Decimal128, oid::ObjectId};
use serde::{Deserialize, Serialize};
use std::env;

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::{PasswordHasher, PasswordVerifier};
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, SaltString};

use crate::AppState;
use crate::models::user::User;

// TODO: Integrate actual Monero RPC for wallet address generation.
// For now, using a placeholder function.
async fn generate_wallet_address(_email: &str) -> String {
    // Placeholder - in production, use state.rpc.create_address(...)
    "generated_monero_address_placeholder".to_string()
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let db = &state.db;
    let collection: Collection<User> = db.collection("users");

    // Check if email already exists
    if collection
        .find_one(mongodb::bson::doc! { "email": &req.email }, None)
        .await
        .unwrap_or(None)
        .is_some()
    {
        return (StatusCode::BAD_REQUEST, "Email already exists".to_string()).into_response();
    }

    // Generate salt and hash password
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 8, 4, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Generate wallet address
    let wallet_address = generate_wallet_address(&req.email).await;

    // Create user
    let now = DateTime::now();
    let balance = "0".parse::<Decimal128>().expect("Failed to parse decimal");

    let user = User {
        id: None,
        email: req.email,
        password_hash,
        wallet_address,
        balance,
        created_at: now,
        updated_at: now,
    };

    // Insert user
    let result = collection.insert_one(user, None).await.unwrap();
    let id = result.inserted_id.as_object_id().unwrap();

    (StatusCode::CREATED, format!("User created with id: {}", id)).into_response()
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    let db = &state.db;
    let collection: Collection<User> = db.collection("users");

    if let Some(user) = collection
        .find_one(mongodb::bson::doc! { "email": &req.email }, None)
        .await
        .unwrap()
    {
        let params = Params::new(65536, 8, 4, Some(32)).unwrap();
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
        if argon2
            .verify_password(req.password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            let claims = Claims {
                sub: user.id.unwrap().to_hex(),
                exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
            };
            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .unwrap();

            let cookie = format!(
                "token={}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict",
                token
            );

            return (
                StatusCode::OK,
                [("Set-Cookie", cookie.as_str())],
                "Login successful".to_string(),
            )
                .into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()).into_response()
}

pub fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
}
