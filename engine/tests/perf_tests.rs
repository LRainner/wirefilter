use wirefilter::{ExecutionContext, LhsValue, Scheme};
use std::net::IpAddr;
use std::str::FromStr;

/// Test: Scheme clone cost — ExecutionContext::new clones the Scheme (Arc clone).
/// This is cheap (Arc::clone is just an atomic increment), but if you create
/// many contexts per second it adds up. The test verifies correctness and
/// hints at the pattern of reusing a single context.
#[test]
fn test_execution_context_reuse_vs_recreate() {
    let scheme = Scheme! {
        http.method: Bytes,
        http.ua: Bytes,
        ip.src: Ip,
        tcp.port: Int,
    }
    .build();

    let filter = scheme
        .parse(r#"http.method == "GET" && tcp.port == 443"#)
        .unwrap()
        .compile();

    // Pattern 1: Recreate context each time (wasteful — clones Scheme each time)
    for _ in 0..100 {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        ctx.set_field_value(scheme.get_field("http.method").unwrap(), "GET")
            .unwrap();
        ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 443)
            .unwrap();
        assert_eq!(filter.execute(&ctx).unwrap(), true);
    }

    // Pattern 2: Reuse a single context with clear() (no Scheme clone)
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    for port in [443, 80, 8080, 443, 443] {
        ctx.clear();
        ctx.set_field_value(scheme.get_field("http.method").unwrap(), "GET")
            .unwrap();
        ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), port)
            .unwrap();
        assert_eq!(
            filter.execute(&ctx).unwrap(),
            port == 443,
            "expected match only for port 443, got match for port {port}"
        );
    }
}

/// Test: Each AST node compiles to a Box<dyn Fn> — indirect call overhead.
/// A filter with many terms creates a deep closure tree. Verify correctness
/// and that execution still works with deeply nested expressions.
#[test]
fn test_deep_filter_closures() {
    let scheme = Scheme! {
        f0: Int,
        f1: Int,
        f2: Int,
        f3: Int,
        f4: Int,
        f5: Int,
        f6: Int,
        f7: Int,
    }
    .build();

    // Build a deeply nested AND filter — each term is a separate boxed closure
    let filter_str = "f0 == 0 && f1 == 1 && f2 == 2 && f3 == 3 && f4 == 4 && f5 == 5 && f6 == 6 && f7 == 7";
    let filter = scheme.parse(filter_str).unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    for i in 0..8u8 {
        let name = format!("f{i}");
        ctx.set_field_value(scheme.get_field(&name).unwrap(), i64::from(i))
            .unwrap();
    }
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Change one field — should short-circuit AND and return false
    ctx.set_field_value(scheme.get_field("f3").unwrap(), 999i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

/// Test: Large `in {}` set — list matching is O(n) linear scan for exact matches.
/// This test verifies correctness with a large set and hints at the performance concern.
#[test]
fn test_large_in_set_matching() {
    let scheme = Scheme! {
        tcp.port: Int,
    }
    .build();

    // Build a filter with a large set — list matching iterates through all entries
    let mut filter_str = String::from("tcp.port in {");
    for port in 1..=200u16 {
        if port > 1 {
            filter_str.push(' ');
        }
        filter_str.push_str(&port.to_string());
    }
    filter_str.push('}');

    let filter = scheme.parse(&filter_str).unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // Value at the start of the set
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 1i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Value in the middle
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 100i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Value at the end
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 200i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Value not in the set
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 201i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

/// Test: XOR does NOT short-circuit — all sub-expressions are always evaluated.
/// Unlike AND/OR which short-circuit, XOR must evaluate every term.
#[test]
fn test_xor_no_short_circuit() {
    let scheme = Scheme! {
        a: Bool,
        b: Bool,
    }
    .build();

    let filter = scheme.parse("a xor b").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // true xor false = true
    ctx.set_field_value(scheme.get_field("a").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx.set_field_value(scheme.get_field("b").unwrap(), LhsValue::Bool(false))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // true xor true = false
    ctx.set_field_value(scheme.get_field("b").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

/// Test: Repeated parse+compile is expensive. The compile step creates boxed
/// closures for each node. Verify that pre-compiling once and executing many
/// times is the correct and efficient pattern.
#[test]
fn test_parse_once_execute_many() {
    let scheme = Scheme! {
        ip.src: Ip,
        tcp.port: Int,
        http.host: Bytes,
    }
    .build();

    let filter = scheme
        .parse(r#"ip.src == 127.0.0.1 && tcp.port >= 1024 && http.host == "localhost""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("127.0.0.1").unwrap(),
    )
    .unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 8080i64)
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.host").unwrap(), "localhost")
        .unwrap();

    // Execute the same compiled filter 1000 times — should be fast
    for _ in 0..1000 {
        assert_eq!(filter.execute(&ctx).unwrap(), true);
    }
}

/// Test: IPv4 CIDR matching with a large set of ranges.
/// `in { ... }` with CIDR ranges uses RangeSet, which internally uses
/// binary search (O(log n)), unlike exact-value sets which are O(n) linear scan.
#[test]
fn test_ip_cidr_large_set() {
    let scheme = Scheme! {
        ip.src: Ip,
    }
    .build();

    // Cloudflare-like IP range list
    let filter = scheme
        .parse(
            r#"ip.src in { 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 }"#
        )
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // IP inside 173.245.48.0/20
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("173.245.48.1").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // IP not in any range
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("1.2.3.4").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

/// Test: set_field_value performs a runtime type check every time.
/// This is a boundary check (correct), but if you set the same field
/// many times per second it adds overhead.
#[test]
fn test_set_field_value_type_check_overhead() {
    let scheme = Scheme! {
        tcp.port: Int,
        http.host: Bytes,
    }
    .build();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // Setting values many times — each call does type + scheme equality check
    for i in 0..1000u64 {
        ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), i as i64)
            .unwrap();
        ctx.set_field_value(scheme.get_field("http.host").unwrap(), "example.com")
            .unwrap();
    }

    // Verify final value
    assert_eq!(
        ctx.get_field_value(scheme.get_field("tcp.port").unwrap()),
        Some(&LhsValue::Int(999))
    );
}
