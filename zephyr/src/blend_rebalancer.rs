use serde::{Deserialize, Serialize};
use serde_json::json;
use zephyr_sdk::{prelude::*, protocols::blend::{storage::Request, BlendPoolWrapper}, soroban_sdk::{xdr::{FeeBumpTransactionInnerTx, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, OperationBody, TransactionEnvelope, Limits, ReadXdr, Transaction, TransactionExt, WriteXdr}, IntoVal, Symbol, TryIntoVal, Val}, utils::address_from_str, AgnosticRequest, DatabaseDerive, EnvClient};

const MOCKED: bool = false;

#[derive(DatabaseDerive, Clone, Deserialize, Serialize)]
#[with_name("userinst")]
pub struct UserPositionRebalancer {
    pub pool: String,
    pub p_user: String,
    
    // Mercury will send the envelope to sign and submit to this url
    pub url: String,
    // There will be a Basic Authorization header attached to the request with this value.
    // This is required to let your local service know that the tx submission requets
    // came from an authorized party. Nevertheless, it's good practice to check the transaction
    // and match that it indeed is a blend transaction.
    pub secret: String,
    
    // Upper limit configurations.
    pub up_lim: i64,
    pub up_asst: String,
    pub up_amnt: i64,
    
    // up_conservative.
    // If true, when the HF is greater than the limit the bot will default to decreasing collateral of `up_asst` by `up_amnt`.
    // If false, when the HF is greater than the limit the bot will default to borrowing `up_amnt` of `up_asst``.
    pub up_cons: bool,

    // Bottom limit configurations.
    pub down_lim: i64,
    pub down_asst: String,
    pub down_amnt: i64,
    
    // down_conservative.
    // If true, when the HF is below limit the bot will default to repaying the debt on `down_asst` by `down_amnt`.
    // If false, when the HF is below limit the bot will default to increasing the collateral of `down_asst` by `down_amnt`.
    pub down_cons: bool,
}

impl UserPositionRebalancer {
    /// Creates a new position for the user or updates the existing one.
    pub fn new(env: &EnvClient, pos: &Self) {
        env.log().debug("creating position", None);
        
        let existing: Vec<Self> = env.read_filter()
            .column_equal_to("pool", pos.pool.clone())
            .column_equal_to("p_user", pos.p_user.clone())
            .read().unwrap();
        
        if let Some(_) = existing.get(0) {
            env.update()
                .column_equal_to("pool", pos.pool.clone())
                .column_equal_to("p_user", pos.p_user.clone())
                .execute(pos).unwrap();
        } else {
            env.log().debug("adding new position", None);
            env.put(pos);
        }
    }
}

pub fn add(env: &EnvClient, pos: UserPositionRebalancer) {
    UserPositionRebalancer::new(env, &pos);
}

pub fn main(env: &EnvClient) {
    let mut check = false;
    
    for tx in env.reader().envelopes() {
        let first = match tx {
            TransactionEnvelope::Tx(v1) => &v1.tx.operations.to_vec()[0],
            TransactionEnvelope::TxFeeBump(feebump) => {
                let FeeBumpTransactionInnerTx::Tx(v1) = feebump.tx.inner_tx;
                &v1.tx.operations.to_vec()[0]
            }
            TransactionEnvelope::TxV0(v0) => &v0.tx.operations.to_vec()[0],
        };

        if let OperationBody::InvokeHostFunction(InvokeHostFunctionOp { host_function, .. }) =
            &first.body
        {
            if let HostFunction::InvokeContract(InvokeContractArgs { function_name, .. }) =
                host_function
            {
                if function_name.0.to_string() == "set_price"
                {
                    check = true
                }
            }
        }
    }

    if check {
        check_hfs(env);
    }
}

fn check_hfs(env: &EnvClient) {
    let tracked: Vec<UserPositionRebalancer> = env.read();
    env.log().debug(format!("tracking {} positions.", tracked.len()), None);

    for pos in tracked {
        let mut pool = BlendPoolWrapper::new(env, pos.pool, MOCKED);
        let user_hf = pool.get_user_hf(env, &pos.p_user);

        env.log().debug(format!("User current hf: {}. Range {}-{}.", user_hf.current, pos.down_lim, pos.up_lim), None);
        let mut message = None;
        
        if user_hf.current > pos.up_lim {
            // User HF is too high, need to increase liabilities or diminish collateral.
            if pos.up_cons {
                // User chose conservative strategy, decreasing collateral.
                message = Some(build_request_object(env, pool, pos.p_user, pos.up_asst, pos.up_amnt, 3));
            } else {
                // User chose non conservative strategy, increasing liabilities.
                message = Some(build_request_object(env, pool, pos.p_user, pos.up_asst, pos.up_amnt, 4));
            }
        } else if user_hf.current < pos.down_lim {
            // User HF is too low, need to increase collateral or repay liabilities.
            if pos.down_cons {
                // User chose conservative strategy, repaying debt.
                message = Some(build_request_object(env, pool, pos.p_user, pos.down_asst, pos.down_amnt, 5));
            } else {
                // User chose non conservative strategy, increasing collateral.
                message = Some(build_request_object(env, pool, pos.p_user, pos.down_asst, pos.down_amnt, 2));
            }
        }
        
        if let Some(message) = message {
            let request = AgnosticRequest {
                body: Some(message),
                url: pos.url,
                method: zephyr_sdk::Method::Post,
                headers: vec![("Content-Type".into(), "application/json".into()), ("Authorization".into(), format!("Basic {}", pos.secret))]
            };
            env.send_web_request(request);
        }
    }
}

fn build_request_object(env: &EnvClient, pool: BlendPoolWrapper, user: String, asset: String, usdc_amount: i64, request_type: u32) -> String {
    let price = pool.get_price(env, &asset);
    env.log().debug(format!("got price of {:?}.", price), None);
    let v = usdc_amount as f64 / price;
    let v_1: i128 = (v as i64).try_into().unwrap();
    
    env.log().debug(format!("borrow amount is {:?}.", env.to_scval(v_1)), None);
    
    let request = Request {
        request_type,
        address: address_from_str(env, &asset),
        amount: v_1
    };

    build_tx_from_blend_request(env, pool, &user, request)
}

fn build_tx_from_blend_request(env: &EnvClient, pool: BlendPoolWrapper, source: &str, request: Request) -> String {
    let blend_requests: zephyr_sdk::soroban_sdk::Vec<Request> = zephyr_sdk::soroban_sdk::vec![&env.soroban(), request.clone()];
    let args_val: zephyr_sdk::soroban_sdk::Vec<Val> = (
        address_from_str(env, &source),
        address_from_str(env, &source),
        address_from_str(env, &source),
        blend_requests,
    )
        .try_into_val(env.soroban()).unwrap_or(zephyr_sdk::soroban_sdk::Vec::new(&env.soroban()));

    if args_val.len() == 0 {
        return json!({"status": "error", "message": "failed to convert arguments to host val"}).to_string();
    }

    env.log().debug(format!("getting sequence"), None);

    let sequence = if !MOCKED {
        let account = stellar_strkey::ed25519::PublicKey::from_string(&source)
            .unwrap()
            .0;

        env.read_account_from_ledger(account)
            .unwrap()
            .unwrap()
            .seq_num as i64
            + 1
    } else {
        0
    };

    env.log()
        .debug(format!("about to simulate {:?}", args_val), None);

    let simulation = env.simulate_contract_call_to_tx(
        source.to_string(),
        sequence,
        pool.as_hash(),
        Symbol::new(env.soroban(), "submit"),
        args_val,
    );

    let mut result = json!({"status": "error", "message": "unknown error during simulation"});

    if let Ok(tx_resp) = simulation {
        env.log()
            .debug(format!("TX err: {:?} {:?}", tx_resp.error, tx_resp.tx), None);
        let response = tx_resp.tx.unwrap_or("".into());


        result = json!({"status": "success", "envelope": tamper_resources(response), "request_type": request.request_type});
    }

    result.to_string()
}

fn tamper_resources(tx: String) -> String {
    let mut tx = Transaction::from_xdr_base64(tx, Limits::none()).unwrap();
    let TransactionExt::V1(mut resources) = tx.ext else {panic!()};
    resources.resource_fee -= 167_000;
    tx.ext = TransactionExt::V1(resources);
    tx.to_xdr_base64(Limits::none()).unwrap()
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use stellar_xdr::next::{Hash, Int128Parts, InvokeContractArgs, InvokeHostFunctionOp, Limits, Operation, ScAddress, ScSymbol, ScVal, SequenceNumber, Transaction, TransactionEnvelope, TransactionV1Envelope, Uint256, WriteXdr};
    use zephyr_sdk::protocols::blend::SCALAR_7;
    use zephyr_vm::testutils::{TestHost, Transition, TransitionPretty};

    fn build_transition() -> Transition {
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: stellar_xdr::next::MuxedAccount::Ed25519(Uint256([0; 32])),
                fee: 10000,
                seq_num: SequenceNumber(1),
                cond: stellar_xdr::next::Preconditions::None,
                memo: stellar_xdr::next::Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: stellar_xdr::next::OperationBody::InvokeHostFunction(
                        InvokeHostFunctionOp {
                            auth: vec![].try_into().unwrap(),
                            host_function: stellar_xdr::next::HostFunction::InvokeContract(
                                InvokeContractArgs {
                                    contract_address: ScAddress::Contract(Hash([0; 32])),
                                    function_name: ScSymbol("set_price".try_into().unwrap()),
                                    args: vec![].try_into().unwrap(),
                                },
                            ),
                        },
                    ),
                }]
                .try_into()
                .unwrap(),
                ext: stellar_xdr::next::TransactionExt::V0,
            },
            signatures: vec![].try_into().unwrap(),
        });
        let mut transition = TransitionPretty::new();
        transition.inner.set_sequence(2000);
        transition.inner.set_append(envelope);

        transition.inner
    }


    #[tokio::test]
    async fn test_storage() {
        let env = TestHost::default();
        let mut db = env.database("postgres://postgres:postgres@localhost:5432");
        let mut program = env.new_program("./target/wasm32-unknown-unknown/release/blend_api.wasm");
        let transition = build_transition();

        let created = db
            .load_table(0, "userinst", vec![
                "pool", 
                "p_user",
                "url",
                "secret",
                "up_lim",
                "up_asst",
                "up_amnt",
                "up_cons",
                "down_lim",
                "down_asst",
                "down_amnt",
                "down_cons"
                ], None)
            .await;
        //created.unwrap();
        //assert!(created.is_ok());
        assert_eq!(db.get_rows_number(0, "userinst").await.unwrap(), 0);

        program.set_body(json!({
            "url": "https://tdep.requestcatcher.com/test", "pool": "CCEVW3EEW4GRUZTZRTAMJAXD6XIF5IG7YQJMEEMKMVVGFPESTRXY2ZAV",
            "p_user": "GDNJLAA53XWKR4GC4A7QST45VDZAVFSFMNZESMMS3YQB7FVFBA47HGR5",
            "secret": "thisiscool",
            "up_lim": 10874797,
            "up_asst": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
            "up_amnt": 100 * SCALAR_7 as i64,
            "up_cons": false,
            "down_lim": 10174797,
            "down_asst": "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA",
            "down_amnt": 100 * SCALAR_7 as i64,
            "down_cons": false,
        }).to_string());
        
        let invocation = program.invoke_vm("new_position").await;
        assert!(invocation.is_ok());
        let inner_invocation = invocation.unwrap();
        assert!(inner_invocation.is_ok());

        assert_eq!(db.get_rows_number(0, "userinst").await.unwrap(), 1);

        program.set_transition(transition);

        let invocation = program.invoke_vm("on_close").await;
        assert!(invocation.is_ok());
        let inner_invocation = invocation.unwrap();
        println!("{}", inner_invocation.unwrap().1);
        //assert!(inner_invocation.is_ok());

        // Drop the connection and all the noise created in the local database.
        db.close().await;
    }
}
