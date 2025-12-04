use mongodb::bson::{oid::ObjectId, DateTime, Decimal128};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    pub password_hash: String,
    pub wallet_address: String,
    pub balance: Decimal128,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
