//! Integration tests for ipset/nftset operations.
//!
//! These tests require root privileges.
//! Run with: sudo ./target/debug/deps/integration_tests-*

use std::net::IpAddr;

use ruhop_ipset::{
    ipset_add, ipset_create, ipset_del, ipset_destroy, ipset_test, nftset_add, nftset_create_set,
    nftset_create_table, nftset_del, nftset_delete_table, nftset_test, IpEntry, IpSetCreateOptions,
    IpSetFamily, NftSetCreateOptions, NftSetType,
};

// =====================
// ipset tests
// =====================

mod ipset_tests {
    use super::*;

    const SET_NAME: &str = "ruhop_test_set";
    const SET_NAME_V6: &str = "ruhop_test_set6";
    const SET_NAME_TIMEOUT: &str = "ruhop_test_timeout";

    fn setup_ipset() {
        // Destroy first in case it exists
        let _ = ipset_destroy(SET_NAME);
        let opts = IpSetCreateOptions::default();
        ipset_create(SET_NAME, &opts).expect("Failed to create ipset");
    }

    fn setup_ipset_v6() {
        let _ = ipset_destroy(SET_NAME_V6);
        let opts = IpSetCreateOptions {
            family: IpSetFamily::Inet6,
            ..Default::default()
        };
        ipset_create(SET_NAME_V6, &opts).expect("Failed to create ipset6");
    }

    fn setup_ipset_timeout() {
        let _ = ipset_destroy(SET_NAME_TIMEOUT);
        let opts = IpSetCreateOptions {
            timeout: Some(300),
            ..Default::default()
        };
        ipset_create(SET_NAME_TIMEOUT, &opts).expect("Failed to create ipset with timeout");
    }

    fn cleanup_ipset() {
        let _ = ipset_destroy(SET_NAME);
        let _ = ipset_destroy(SET_NAME_V6);
        let _ = ipset_destroy(SET_NAME_TIMEOUT);
    }

    #[test]
    fn test_ipset_add_test_del_ipv4() {
        setup_ipset();

        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Test that IP is not in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP");
        assert!(!exists, "IP should not exist initially");

        // Add IP to set
        ipset_add(SET_NAME, addr).expect("Failed to add IP");

        // Test that IP is now in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP after add");
        assert!(exists, "IP should exist after add");

        // Delete IP from set
        ipset_del(SET_NAME, addr).expect("Failed to delete IP");

        // Test that IP is no longer in set
        let exists = ipset_test(SET_NAME, addr).expect("Failed to test IP after del");
        assert!(!exists, "IP should not exist after delete");

        cleanup_ipset();
    }

    #[test]
    fn test_ipset_add_test_del_ipv6() {
        setup_ipset_v6();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();

        // Test that IP is not in set
        let exists = ipset_test(SET_NAME_V6, addr).expect("Failed to test IPv6");
        assert!(!exists, "IPv6 should not exist initially");

        // Add IP to set
        ipset_add(SET_NAME_V6, addr).expect("Failed to add IPv6");

        // Test that IP is now in set
        let exists = ipset_test(SET_NAME_V6, addr).expect("Failed to test IPv6 after add");
        assert!(exists, "IPv6 should exist after add");

        // Delete IP from set
        ipset_del(SET_NAME_V6, addr).expect("Failed to delete IPv6");

        // Test that IP is no longer in set
        let exists = ipset_test(SET_NAME_V6, addr).expect("Failed to test IPv6 after del");
        assert!(!exists, "IPv6 should not exist after delete");

        cleanup_ipset();
    }

    #[test]
    fn test_ipset_with_timeout() {
        setup_ipset_timeout();

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);

        // Add IP with timeout
        ipset_add(SET_NAME_TIMEOUT, entry).expect("Failed to add IP with timeout");

        // Test that IP is in set
        let exists = ipset_test(SET_NAME_TIMEOUT, addr).expect("Failed to test IP");
        assert!(exists, "IP should exist after add with timeout");

        cleanup_ipset();
    }

    #[test]
    fn test_ipset_multiple_ips() {
        setup_ipset();

        let addrs: Vec<IpAddr> = vec![
            "10.0.0.10".parse().unwrap(),
            "10.0.0.11".parse().unwrap(),
            "10.0.0.12".parse().unwrap(),
        ];

        // Add all IPs
        for addr in &addrs {
            ipset_add(SET_NAME, *addr).expect("Failed to add IP");
        }

        // Test all IPs exist
        for addr in &addrs {
            let exists = ipset_test(SET_NAME, *addr).expect("Failed to test IP");
            assert!(exists, "IP {} should exist", addr);
        }

        // Delete all IPs
        for addr in &addrs {
            ipset_del(SET_NAME, *addr).expect("Failed to delete IP");
        }

        // Test all IPs are gone
        for addr in &addrs {
            let exists = ipset_test(SET_NAME, *addr).expect("Failed to test IP");
            assert!(!exists, "IP {} should not exist after delete", addr);
        }

        cleanup_ipset();
    }

    #[test]
    fn test_ipset_nonexistent_set() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        let result = ipset_add("nonexistent_set_12345", addr);
        assert!(result.is_err(), "Should fail for nonexistent set");
    }
}

// =====================
// nftset tests
// =====================

mod nftset_tests {
    use super::*;

    const TABLE_NAME: &str = "ruhop_test_table";
    const SET_NAME: &str = "ruhop_test_set";
    const SET_NAME_V6: &str = "ruhop_test_set6";
    const SET_NAME_TIMEOUT: &str = "ruhop_test_timeout";

    fn setup_nftset() {
        // Clean up first
        let _ = nftset_delete_table("inet", TABLE_NAME);

        // Create table
        nftset_create_table("inet", TABLE_NAME).expect("Failed to create table");

        // Create set
        let opts = NftSetCreateOptions::default();
        nftset_create_set("inet", TABLE_NAME, SET_NAME, &opts).expect("Failed to create set");
    }

    fn setup_nftset_v6() {
        let opts = NftSetCreateOptions {
            set_type: NftSetType::Ipv6Addr,
            ..Default::default()
        };
        nftset_create_set("inet", TABLE_NAME, SET_NAME_V6, &opts).expect("Failed to create set6");
    }

    fn setup_nftset_timeout() {
        let opts = NftSetCreateOptions {
            timeout: Some(300),
            ..Default::default()
        };
        nftset_create_set("inet", TABLE_NAME, SET_NAME_TIMEOUT, &opts)
            .expect("Failed to create set with timeout");
    }

    fn cleanup_nftset() {
        let _ = nftset_delete_table("inet", TABLE_NAME);
    }

    #[test]
    fn test_nftset_add_test_del_ipv4() {
        setup_nftset();

        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        // Test that IP is not in set
        let exists =
            nftset_test("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to test IP");
        assert!(!exists, "IP should not exist initially");

        // Add IP to set
        nftset_add("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to add IP");

        // Test that IP is now in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME, addr)
            .expect("Failed to test IP after add");
        assert!(exists, "IP should exist after add");

        // Delete IP from set
        nftset_del("inet", TABLE_NAME, SET_NAME, addr).expect("Failed to delete IP");

        // Test that IP is no longer in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME, addr)
            .expect("Failed to test IP after del");
        assert!(!exists, "IP should not exist after delete");

        cleanup_nftset();
    }

    #[test]
    fn test_nftset_add_test_del_ipv6() {
        setup_nftset();
        setup_nftset_v6();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();

        // Test that IP is not in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME_V6, addr)
            .expect("Failed to test IPv6");
        assert!(!exists, "IPv6 should not exist initially");

        // Add IP to set
        nftset_add("inet", TABLE_NAME, SET_NAME_V6, addr).expect("Failed to add IPv6");

        // Test that IP is now in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME_V6, addr)
            .expect("Failed to test IPv6 after add");
        assert!(exists, "IPv6 should exist after add");

        // Delete IP from set
        nftset_del("inet", TABLE_NAME, SET_NAME_V6, addr).expect("Failed to delete IPv6");

        // Test that IP is no longer in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME_V6, addr)
            .expect("Failed to test IPv6 after del");
        assert!(!exists, "IPv6 should not exist after delete");

        cleanup_nftset();
    }

    #[test]
    fn test_nftset_with_timeout() {
        setup_nftset();
        setup_nftset_timeout();

        let addr: IpAddr = "10.0.0.2".parse().unwrap();
        let entry = IpEntry::with_timeout(addr, 60);

        // Add IP with timeout
        nftset_add("inet", TABLE_NAME, SET_NAME_TIMEOUT, entry)
            .expect("Failed to add IP with timeout");

        // Test that IP is in set
        let exists = nftset_test("inet", TABLE_NAME, SET_NAME_TIMEOUT, addr)
            .expect("Failed to test IP");
        assert!(exists, "IP should exist after add with timeout");

        cleanup_nftset();
    }

    #[test]
    fn test_nftset_multiple_ips() {
        setup_nftset();

        let addrs: Vec<IpAddr> = vec![
            "10.0.0.10".parse().unwrap(),
            "10.0.0.11".parse().unwrap(),
            "10.0.0.12".parse().unwrap(),
        ];

        // Add all IPs
        for addr in &addrs {
            nftset_add("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to add IP");
        }

        // Test all IPs exist
        for addr in &addrs {
            let exists = nftset_test("inet", TABLE_NAME, SET_NAME, *addr)
                .expect("Failed to test IP");
            assert!(exists, "IP {} should exist", addr);
        }

        // Delete all IPs
        for addr in &addrs {
            nftset_del("inet", TABLE_NAME, SET_NAME, *addr).expect("Failed to delete IP");
        }

        // Test all IPs are gone
        for addr in &addrs {
            let exists = nftset_test("inet", TABLE_NAME, SET_NAME, *addr)
                .expect("Failed to test IP");
            assert!(!exists, "IP {} should not exist after delete", addr);
        }

        cleanup_nftset();
    }

    #[test]
    fn test_nftset_nonexistent_set() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();

        let result = nftset_add("inet", "nonexistent_table", "nonexistent_set", addr);
        assert!(result.is_err(), "Should fail for nonexistent set");
    }
}
