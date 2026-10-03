pub fn check_issuer_home_domain(home_domain: Option<&str>) -> bool {
    // Fix: Flags an issuer with no home_domain as strictly unattributable.
    home_domain.is_some()
}
