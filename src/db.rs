use anyhow::Result;
use mongodb::{Client, options::ClientOptions};
use std::env;

pub async fn connect_to_mongo() -> Result<mongodb::Database> {
    let uri = env::var("MONGODB_URI")
        .unwrap_or_else(|_| "mongodb://localhost:27017/coinflip_db".to_string());

    println!("Using MongoDB URI: {}", uri);
    let client_options = ClientOptions::parse(&uri).await?;
    let client = Client::with_options(client_options)?;

    let db = client.database("coinflip_db");

    // Test the connection
    db.run_command(mongodb::bson::doc! {"ping": 1}, None)
        .await?;

    Ok(db)
}
