use blend_rebalancer::UserPositionRebalancer;
use zephyr_sdk::EnvClient;
mod blend_rebalancer;

#[no_mangle]
pub extern "C" fn on_close() {
    let env = EnvClient::new();
    blend_rebalancer::main(&env);
}

#[no_mangle]
pub extern "C" fn new_position() {
    let env = EnvClient::empty();
    let body: UserPositionRebalancer = env.read_request_body();

    blend_rebalancer::add(&env, body);
}
