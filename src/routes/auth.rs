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
use rand::rngs::OsRng;

use crate::AppState;
use crate::models::user::User;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{Result, anyhow};
use bip39::{Language, Mnemonic};
use hex;
use lazy_static::lazy_static;
use monero::{Address, Network, PrivateKey, PublicKey};
use rand::RngCore;
use rand::thread_rng;

// Server key for encrypting seeds (use a strong, unique key in production)
lazy_static! {
    static ref SERVER_KEY: Key<Aes256Gcm> = {
        let key_str = std::env::var("SEED_ENCRYPTION_KEY")
            .unwrap_or_else(|_| "default_key_replace_in_prod_32bytes!".to_string());
        let mut key_bytes = [0u8; 32];
        let key_data = key_str.as_bytes();
        let len = key_data.len().min(32);
        key_bytes[..len].copy_from_slice(&key_data[..len]);
        Key::<Aes256Gcm>::from(key_bytes)
    };
}

async fn generate_wallet_address(_state: &AppState, _email: &str) -> Result<(String, String)> {
    // Generate a real 24-word mnemonic (standard BIP39, close to Monero)
    let mut entropy = [0u8; 32];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| anyhow!("Failed to generate mnemonic: {}", e))?;

    // For address, generate as before (random valid keys)
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

    Ok((address.to_string(), mnemonic.to_string()))
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
    let (wallet_address, plain_seed) = match generate_wallet_address(&state, &req.email).await {
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

    // Encrypt the seed for storage
    let cipher = Aes256Gcm::new(&*SERVER_KEY);
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = match cipher.encrypt(&nonce, plain_seed.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Encryption failed: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate wallet".to_string(),
            )
                .into_response();
        }
    };
    let encrypted_seed = format!("{}:{}", hex::encode(nonce), hex::encode(&ciphertext));

    // Create user with encrypted seed
    let now = DateTime::now();
    let balance = "0".parse::<Decimal128>().expect("Failed to parse decimal");

    let user = User {
        id: None,
        email: req.email,
        password_hash: password_hash.clone(),
        wallet_address: wallet_address.clone(),
        seed: encrypted_seed,
        balance,
        created_at: now,
        updated_at: now,
    };

    // Insert user
    let result = collection.insert_one(user, None).await.unwrap();
    let id = result.inserted_id.as_object_id().unwrap();

    // Return seed to user (they must back it up; server can't recover encrypted seed)
    // TODO: Remove seed from response in production for security
    (
        StatusCode::CREATED,
        format!(
            "User created with id: {}. Address: {}. Seed (BACKUP SECURELY): {}",
            id, wallet_address, plain_seed
        ),
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
