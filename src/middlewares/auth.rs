use axum::body::Body;
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{
        StatusCode,
        header::COOKIE,
        request::{Parts, Request},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::Deserialize;
use std::env;

#[derive(Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn auth_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    let (mut parts, body) = req.into_parts();
    let cookie_header = match parts.headers.get(COOKIE) {
        Some(value) => value.to_str().unwrap_or(""),
        None => return (StatusCode::UNAUTHORIZED, "Missing cookie").into_response(),
    };

    let token = cookie_header
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("token="))
        .map(|s| s.to_string());

    let token = match token {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let decoding_key = DecodingKey::from_secret(secret.as_ref());

    match decode::<Claims>(&token, &decoding_key, &Validation::default()) {
        Ok(token_data) => {
            // Attach user ID to extensions
            parts.extensions.insert(token_data.claims.sub);
            let req = Request::from_parts(parts, body);
            next.run(req).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    }
}

// Extension to extract user_id from request
#[derive(Clone)]
pub struct UserId(pub String);

#[async_trait]
impl<S> FromRequestParts<S> for UserId
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<String>()
            .cloned()
            .map(UserId)
            .ok_or((StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}
