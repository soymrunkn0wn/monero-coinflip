use mongodb::bson::{DateTime, Decimal128, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub user_id: ObjectId,
    #[serde(rename = "type")]
    pub transaction_type: String,
    pub amount: Decimal128,
    pub tx_hash: Option<String>,
    pub status: String,
    pub created_at: DateTime,
}
