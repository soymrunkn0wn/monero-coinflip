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
use password_hash::{PasswordHash, SaltString};
use rand::{RngCore, rngs::OsRng};

use crate::AppState;
use crate::models::user::User;
use anyhow::{Result, anyhow};
use hex;
use monero::{Address, Network, PrivateKey, PublicKey};

async fn generate_wallet_address(_state: &AppState, _email: &str) -> Result<(String, String)> {
    // Generate random entropy for seed
    let mut entropy = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut entropy);

    // For simplicity, create a placeholder seed and address
    // TODO: Implement proper mnemonic and key derivation using monero crate
    let seed = format!("{}...placeholder_seed", hex::encode(&entropy[0..8]));

    // Generate valid public keys by looping until valid
    let public_spend = loop {
        let mut spend_bytes = [0u8; 32];
        rng.fill_bytes(&mut spend_bytes);
        if let Ok(pk) = PublicKey::from_slice(&spend_bytes) {
            break pk;
        }
    };

    let public_view = loop {
        let mut view_bytes = [0u8; 32];
        rng.fill_bytes(&mut view_bytes);
        if let Ok(pk) = PublicKey::from_slice(&view_bytes) {
            break pk;
        }
    };

    let address = Address::standard(Network::Testnet, public_spend, public_view);

    Ok((address.to_string(), seed))
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

    // Generate wallet address and seed
    let (wallet_address, seed) = match generate_wallet_address(&state, &req.email).await {
        Ok((addr, sd)) => (addr, sd),
        Err(e) => {
            eprintln!("Error generating wallet and seed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate wallet".to_string(),
            )
                .into_response();
        }
    };

    // Create user
    let now = DateTime::now();
    let balance = "0".parse::<Decimal128>().expect("Failed to parse decimal");

    let user = User {
        id: None,
        email: req.email,
        password_hash,
        wallet_address,
        seed: seed.clone(),
        balance,
        created_at: now,
        updated_at: now,
    };

    // Insert user
    let result = collection.insert_one(user, None).await.unwrap();
    let id = result.inserted_id.as_object_id().unwrap();

    // TODO: Secure seed handling - do not expose in production
    (
        StatusCode::CREATED,
        format!("User created with id: {}. Seed: {}", id, seed.clone()),
    )
        .into_response()
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
