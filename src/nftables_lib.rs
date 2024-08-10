fn run<T: ToString>(
    family: &str,
    table: &str,
    set: &str,
    flush: bool,
    items: impl IntoIterator<T>,
) {
    let nft = libnftables1_sys::Nftables::new();
    let mut cmd = String::new();
    if flush {
        cmd.push_str(&format!("flush set {family} {table} {set}"));
        nft.run_cmd(c)
    }
    nft.set_numeric_time
}
