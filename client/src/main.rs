use clap::{Parser, Subcommand};
use from_zephyrsdk::sign_transaction;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use stellar_xdr::next::{Limits, ReadXdr, Transaction, TransactionEnvelope, TransactionV1Envelope};
use urlencoding::encode;
use std::process::{exit, Command};
use ngrok::prelude::*;
use std::net::SocketAddr;

use axum::{
    extract::ConnectInfo, routing::{get, post}, Json, Router
};

const SECRET: &str = env!("SECRET");
//const SECRET: &str = "";

mod from_zephyrsdk {
    use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey, VerifyingKey};
    use sha2::{Sha256, Digest};
    use stellar_xdr::next::{DecoratedSignature, Hash, Limits, Signature, SignatureHint, Transaction, TransactionEnvelope, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, TransactionV1Envelope, WriteXdr};

    /// Hash a stellar transaction.
    pub fn sha256(payload: &[u8]) -> [u8; 32] {
        Sha256::digest(payload).into()
    }

    /// Hash a stellar transaction.
    pub fn hash_transaction(tx: &Transaction, network_passphrase: &str) -> Result<[u8; 32], stellar_xdr::next::Error> {
        let signature_payload = TransactionSignaturePayload {
            network_id: Hash(Sha256::digest(network_passphrase).into()),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
        };
        Ok(Sha256::digest(signature_payload.to_xdr(Limits::none())?).into())
    }

    /// Sign any payload.
    pub fn ed25519_sign(secret_key: &str, payload: &[u8]) -> (VerifyingKey, [u8; 64]) {
        let mut signing = SigningKey::from_bytes(
            &stellar_strkey::ed25519::PrivateKey::from_string(secret_key)
                .unwrap()
                .0,
        );

        (signing.verifying_key(), signing.sign(payload).to_bytes().try_into().unwrap())
    }

    /// Sign a stellar transaction.
    pub fn sign_transaction(tx: Transaction, network_passphrase: &str, secret_key: &str) -> String {
        let tx_hash = hash_transaction(&tx, network_passphrase).unwrap();
        let (verifying, tx_signature) = ed25519_sign(secret_key, &tx_hash);

        let decorated_signature = DecoratedSignature {
            hint: SignatureHint(verifying.to_bytes()[28..].try_into().unwrap()),
            signature: Signature(tx_signature.try_into().unwrap()),
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: [decorated_signature].try_into().unwrap(),
        });

        envelope.to_xdr_base64(Limits::none()).unwrap()
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Deploy {
        #[arg(long)]
        jwt: String,
        #[arg(long)]
        path: String
    },
    NewPosition {
        #[arg(long)]
        pool: String,
        #[arg(long)]
        p_user: String,
        #[arg(long)]
        up_lim: i64,
        #[arg(long)]
        up_asst: String,
        #[arg(long)]
        up_amnt: i64,
        #[arg(long)]
        up_cons: bool,
        #[arg(long)]
        down_lim: i64,
        #[arg(long)]
        down_asst: String,
        #[arg(long)]
        down_amnt: i64,
        #[arg(long)]
        down_cons: bool,
        #[arg(long)]
        jwt: String,
        #[arg(long)]
        url: String
    },
    Listen {},
}

#[derive(Serialize, Deserialize)]
struct Position {
    url: String,
    pool: String,
    p_user: String,
    secret: String,
    up_lim: i64,
    up_asst: String,
    up_amnt: i64,
    up_cons: bool,
    down_lim: i64,
    down_asst: String,
    down_amnt: i64,
    down_cons: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Deploy { jwt, path } => {
            println!("Deploying...");

            let output = Command::new("sh")
                .arg("-c")
                .arg(format!("cd {} && mercury-cli --jwt {} --mainnet false deploy", path, jwt))
                .output()?;
            println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
            println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        }
        Commands::NewPosition {
            pool,
            p_user,
            up_lim,
            up_asst,
            up_amnt,
            up_cons,
            down_lim,
            down_asst,
            down_amnt,
            down_cons,
            jwt,
            url
        } => {
            let position = Position {
                url,
                pool,
                p_user,
                secret: SECRET.to_string(),
                up_lim,
                up_asst,
                up_amnt,
                up_cons,
                down_lim,
                down_asst,
                down_amnt,
                down_cons,
            };

            let client = reqwest::Client::new();
            let resp = client
                .post("https://api.mercurydata.app/zephyr/execute")
                .header("Authorization", format!("Bearer {}", jwt))
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({
                    "project_name": "blend-balancer",
                    "mode": {
                        "Function": {
                            "fname": "new_position",
                            "arguments": serde_json::to_string(&position)?
                        }
                    }
                }))
                .send()
                .await?;

            println!("Response: {:?}", resp.text().await?);
        }
        Commands::Listen { } => {
            if std::env::var("WALLET_SECRET").is_err() {
                println!("Add WALLET_SECRET env variable");
                exit(0)
            }
            launch_listener().await;
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionResponse {
    pub status: Option<String>,
    pub envelope: Option<String>,
    pub request_type: Option<u32>
}

async fn handle_request(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<TransactionResponse>,
) {
    if let Some(auth) = headers.get("Authorization") {
        if auth == format!("Basic {}", SECRET).as_str() {
            println!("Authorized request from {}", addr);
            let envelope = payload.envelope.unwrap();
            let tx = Transaction::from_xdr_base64(envelope.clone(), Limits::none());
            let signed = sign_transaction(tx.unwrap(), "Test SDF Network ; September 2015", &std::env::var("WALLET_SECRET").unwrap());

            let response = reqwest::blocking::Client::new()
                .post(format!("https://horizon-testnet.stellar.org/transactions"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(format!("tx={}", encode(&signed)))
                .send().unwrap()
                .text().unwrap();

            println!("Executed transaction, response: {}\n", response);

            return;
        }
    }
    println!("Unauthorized request from {}", addr);
}

async fn launch_listener() -> anyhow::Result<()> {
    let app = Router::new().route(
        "/",
        post(handle_request),
    );

    let tun = ngrok::Session::builder()
        .authtoken_from_env()
        .connect()
        .await?
        .http_endpoint()
        .listen()
        .await?;

    println!("Tunnel started on URL: {:?}", tun.url());
    axum::Server::builder(tun)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();

    Ok(())
}

#[test]
fn t() {
    println!("{:?}", Transaction::from_xdr_base64("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", Limits::none()));
}
