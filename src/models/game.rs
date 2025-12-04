use mongodb::bson::{oid::ObjectId, DateTime, Decimal128};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Game {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub creator_id: ObjectId,
    pub opponent_id: Option<ObjectId>,
    pub wager: Decimal128,
    pub status: String,
    pub outcome: Option<String>,
    pub winner_id: Option<ObjectId>,
    pub platform_fee: Option<Decimal128>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
