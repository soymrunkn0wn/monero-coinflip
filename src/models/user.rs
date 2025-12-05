use mongodb::bson::{DateTime, Decimal128, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    pub password_hash: String,
    pub wallet_address: String,
    pub seed: String, // TODO: Encrypt this in production
    pub balance: Decimal128,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
