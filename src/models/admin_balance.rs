use mongodb::bson::{Decimal128, oid::ObjectId};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminBalance {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub balance: Decimal128,
}

impl Default for AdminBalance {
    fn default() -> Self {
        Self {
            id: Some(ObjectId::new()),
            balance: Decimal128::from_str("0").unwrap(),
        }
    }
}
