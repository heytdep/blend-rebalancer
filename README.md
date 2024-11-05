# Blend Rebalancer

A self-custodial worker to rebalance your user's blend positions to keep the health factory within a certain defined range.

> Note: I don't advise to use on mainnet yet. There has been no propert testing about the program's uptime and stability. Relying
on it to balance positions on mainnet may result in loss of funds. Use at your own discretion.

# Requirements

Since this doesn't implement smart wallets yet, the client is required to run a listener to sign and submit transactions
streamed from the zephyr bot. This listener relies on `ngrok` to proxy and safeguard the client's ip.

Requirements:
- `ngrok` and a ngrok token (you can obtain with free plan).
- Rust installed (see https://rustup.rs) with the wasm target (`rustup target add wasm32-unknown-unknown`).
- The Mercury CLI (`cargo install mercury-cli`).
- A [mercury](https://mercurydata.app/) testnet account. 

# Usage

1. Clone the repo.

```
git clone https://github.com/heytdep/blend-rebalancer
```

2. Generate any kind of secret. This will be used so that only those in possession of your secret
can submit transaction requests (nevertheless on mainnet it's advised to check the txs validity client-side).

3. Cd and build the client.

```
cd blend-rebalancer/client; SECRET="ANY_KIND_OF_SECRET_HERE" cargo build --release
```

4. Deploy the zephyr bot (you can obtain the mercury JWT in the testnet dashboard under "Get JWT Token"):

```
../client/target/release/client deploy --jwt MERCURY_JWT_HERE --path ../zephyr
```

5. Wait for the build and deployment to finish. Once that's done, start the listener.

```
WALLET_SECRET="SECRET_THAT_WILL_SIGN_TXS" NGROK_AUTHTOKEN="NGROK_AUTH_TOKEN" ./target/release/client listen
```

6. Once the listener is started, it will tell you at which url it's listening for transactions, copy the URL.

7. Create a new user to track.

```
NGROK_AUTHTOKEN="2oOIvOHjeck4TfCHGKFAL3wWWgF_5kgughKbbcN3tXKo4xj9U" ../client/target/release/client new-position \
  --pool BLEND_POOL_TO_TRACK \
  --p-user USER_TO_TRACK \
  --up-lim UP_LIMIT \
  --up-asst UP_ASSET \
  --up-amnt UP_AMOUNT \
  --up-cons true_OR_false \
  --down-lim DOWN_LIMIT \
  --down-asst DOWN_ASSET \
  --down-amnt DOWN_AMOUNT \
  --down-cons true_OR_false \
  --jwt MERCURY_JWT --url https://{{somengrokaddress_place_yours_here}}.ngrok-free.app
```

Where
- `UP_LIMIT` is the upper bound of the health factor range the user wishes to keep.
- `--up-cons` allows specifying what the user wants to make happen when the health factor is over the upper bound (`UP_LIMIT`). If `true`, the bot will formulate a transaction to increase the user's debt, if `false` one to decrease the collateral.
- `UP_ASSET` is the asset that will either be borrowed or withdrawed depending on `--up-cons`.
- `UP_AMOUNT` is the amount in usdc that will be either borrowed or withdrawed.

- `DOWN_LIMIT` is the lower bound of the health factor range the user wishes to keep.
- `--down-cons` allows specifying what the user wants to make happen when the health factor is under the lower bound (`DOWN_LIMIT`). If `true`, the bot will formulate a transaction to repay the user's debt, if `false` one to increase the collateral.
- `DOWN_ASSET` is the asset that will either be repaid or deposited depending on `--up-cons`.
- `DOWN_AMOUNT` is the amount in usdc that will be either repaid or deposited.

Once the position is added, the bot will monitor for price updates from the pool's oracle and for each price update validate your
health factor.
