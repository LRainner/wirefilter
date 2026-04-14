use wirefilter::{
    ExecutionContext, LhsValue, Scheme, SchemeBuilder, Type,
    AllFunction, AnyFunction,
    SimpleFunctionDefinition, SimpleFunctionImpl, SimpleFunctionParam, SimpleFunctionArgKind,
    AlwaysList,
    Bytes, Array, TypedMap,
};
use serde::de::DeserializeSeed;
use std::net::IpAddr;
use std::str::FromStr;

// ===========================================================================
// 1. 基础类型: Bool, Int, Bytes, Ip
// ===========================================================================

#[test]
fn test_bool_field() {
    let scheme = Scheme! { flag: Bool }.build();
    let filter = scheme.parse("flag").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("flag").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("flag").unwrap(), LhsValue::Bool(false))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_int_comparison_operators() {
    let scheme = Scheme! { port: Int }.build();

    let tests: &[(&str, i64, bool)] = &[
        ("port == 80", 80, true),
        ("port == 80", 443, false),
        ("port != 80", 443, true),
        ("port != 80", 80, false),
        ("port > 1024", 8080, true),
        ("port > 1024", 1024, false),
        ("port >= 1024", 1024, true),
        ("port < 1024", 80, true),
        ("port < 1024", 1024, false),
        ("port <= 1024", 1024, true),
        ("port ge 80", 80, true),
        ("port lt 80", 443, false),
    ];

    for (expr, val, expected) in tests {
        let filter = scheme.parse(expr).unwrap().compile();
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        ctx.set_field_value(scheme.get_field("port").unwrap(), *val)
            .unwrap();
        assert_eq!(
            filter.execute(&ctx).unwrap(),
            *expected,
            "expr={:?}, val={}",
            expr,
            val
        );
    }
}

#[test]
fn test_int_bitwise_and() {
    let scheme = Scheme! { flags: Int }.build();

    // flags & 15 checks if any bit in the low nibble is set (i.e., flags & 15 != 0)
    let filter = scheme.parse("flags & 15").unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // 0x01 & 0x0F != 0
    ctx.set_field_value(scheme.get_field("flags").unwrap(), 0x01i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // 0x10 & 0x0F == 0
    ctx.set_field_value(scheme.get_field("flags").unwrap(), 0x10i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_bytes_equality_and_ordering() {
    let scheme = Scheme! { country: Bytes }.build();

    let tests: &[(&str, &str, bool)] = &[
        (r#"country == "US""#, "US", true),
        (r#"country == "US""#, "CN", false),
        (r#"country != "US""#, "CN", true),
        (r#"country > "M""#, "US", true),
        (r#"country > "M""#, "CN", false),  // "CN" < "M" lexicographically
        (r#"country < "M""#, "CN", true),
    ];

    for (expr, val, expected) in tests {
        let filter = scheme.parse(expr).unwrap().compile();
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        ctx.set_field_value(scheme.get_field("country").unwrap(), *val)
            .unwrap();
        assert_eq!(filter.execute(&ctx).unwrap(), *expected, "expr={expr}");
    }
}

#[test]
fn test_ip_v4_and_v6() {
    let scheme = Scheme! { ip: Ip }.build();
    let filter = scheme.parse("ip == 127.0.0.1").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("127.0.0.1").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("10.0.0.1").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);

    // IPv6
    let filter_v6 = scheme.parse("ip == ::1").unwrap().compile();
    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("::1").unwrap(),
    )
    .unwrap();
    assert_eq!(filter_v6.execute(&ctx).unwrap(), true);
}

// ===========================================================================
// 2. 字符串匹配: contains, matches (regex), wildcard
// ===========================================================================

#[test]
fn test_bytes_contains() {
    let scheme = Scheme! { ua: Bytes }.build();
    let filter = scheme
        .parse(r#"ua contains "Googlebot""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("ua").unwrap(),
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("ua").unwrap(),
        "Mozilla/5.0 (X11; Linux x86_64)",
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_bytes_contains_one_of() {
    // Use "in" to check if a bytes value matches any in a set
    let scheme = Scheme! { ua: Bytes }.build();
    let filter = scheme
        .parse(r#"ua in { "Googlebot" "bingbot" "Baiduspider" }"#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("ua").unwrap(), "Googlebot")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("ua").unwrap(), "bingbot")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("ua").unwrap(), "Firefox")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_regex_matches() {
    let scheme = Scheme! { host: Bytes }.build();

    // Basic regex
    let filter = scheme
        .parse(r#"host ~ "example\.(com|org)""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.com")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.org")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.net")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_wildcard_matching() {
    let scheme = Scheme! { host: Bytes }.build();
    let filter = scheme
        .parse(r#"host wildcard "example.*""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.com")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.org")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "test.com")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 3. 集合操作: in { ... } (精确匹配 / CIDR 范围)
// ===========================================================================

#[test]
fn test_int_in_set() {
    let scheme = Scheme! { port: Int }.build();
    let filter = scheme
        .parse("port in { 80 443 8080 }")
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    for (port, expected) in [(80, true), (443, true), (8080, true), (22, false)] {
        ctx.set_field_value(scheme.get_field("port").unwrap(), port)
            .unwrap();
        assert_eq!(filter.execute(&ctx).unwrap(), expected, "port={port}");
    }
}

#[test]
fn test_bytes_in_set() {
    let scheme = Scheme! { method: Bytes }.build();
    let filter = scheme
        .parse(r#"method in { "GET" "POST" "HEAD" }"#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("method").unwrap(), "GET")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("method").unwrap(), "DELETE")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_ip_cidr_ranges() {
    let scheme = Scheme! { ip: Ip }.build();
    let filter = scheme
        .parse("ip in { 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 }")
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    // Private ranges
    for ip_str in &["10.0.0.1", "172.20.0.1", "192.168.1.1"] {
        ctx.set_field_value(
            scheme.get_field("ip").unwrap(),
            IpAddr::from_str(ip_str).unwrap(),
        )
        .unwrap();
        assert_eq!(filter.execute(&ctx).unwrap(), true, "ip={ip_str}");
    }

    // Public range
    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("8.8.8.8").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_ip_range_with_bounds() {
    let scheme = Scheme! { ip: Ip }.build();
    // Range: >= and < to define a subnet
    let filter = scheme
        .parse("ip >= 10.0.0.0 && ip < 10.0.1.0")
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("10.0.0.100").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("ip").unwrap(),
        IpAddr::from_str("10.0.1.0").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 4. 逻辑操作: && / and, || / or, ^^ / xor, ! / not, 括号
// ===========================================================================

#[test]
fn test_logical_and_or_not() {
    let scheme = Scheme! {
        is_admin: Bool,
        is_active: Bool,
    }
    .build();

    // AND
    let f_and = scheme
        .parse("is_admin && is_active")
        .unwrap()
        .compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("is_admin").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx.set_field_value(scheme.get_field("is_active").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(f_and.execute(&ctx).unwrap(), true);
    ctx.set_field_value(scheme.get_field("is_active").unwrap(), LhsValue::Bool(false))
        .unwrap();
    assert_eq!(f_and.execute(&ctx).unwrap(), false);

    // OR
    let f_or = scheme.parse("is_admin || is_active").unwrap().compile();
    assert_eq!(f_or.execute(&ctx).unwrap(), true); // admin=true, active=false

    // NOT
    let f_not = scheme.parse("!is_admin").unwrap().compile();
    assert_eq!(f_not.execute(&ctx).unwrap(), false);
}

#[test]
fn test_operator_precedence() {
    let scheme = Scheme! { a: Bool, b: Bool, c: Bool }.build();

    // "a || b && c" should parse as "a || (b && c)"
    let filter = scheme.parse("a || b && c").unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // a=false, b=true, c=false => (b && c)=false => false || false = false
    ctx.set_field_value(scheme.get_field("a").unwrap(), LhsValue::Bool(false))
        .unwrap();
    ctx.set_field_value(scheme.get_field("b").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx.set_field_value(scheme.get_field("c").unwrap(), LhsValue::Bool(false))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);

    // a=true, b=true, c=false => true || ... = true (short-circuit)
    ctx.set_field_value(scheme.get_field("a").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);
}

#[test]
fn test_parenthesized_expressions() {
    let scheme = Scheme! { a: Bool, b: Bool, c: Bool }.build();

    // "(a || b) && c" overrides precedence
    let filter = scheme.parse("(a || b) && c").unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // a=false, b=true, c=true => (false || true) && true = true
    ctx.set_field_value(scheme.get_field("a").unwrap(), LhsValue::Bool(false))
        .unwrap();
    ctx.set_field_value(scheme.get_field("b").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx.set_field_value(scheme.get_field("c").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // a=false, b=true, c=false => (false || true) && false = false
    ctx.set_field_value(scheme.get_field("c").unwrap(), LhsValue::Bool(false))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 5. Array 和 Map 类型
// ===========================================================================

#[test]
fn test_array_field() {
    let scheme = Scheme! { ports: Array(Int) }.build();

    let filter = scheme.parse("ports[0] == 80").unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("ports").unwrap(),
        Array::from_iter([80i64, 443i64, 8080i64]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Second element
    let filter2 = scheme.parse("ports[1] == 443").unwrap().compile();
    assert_eq!(filter2.execute(&ctx).unwrap(), true);
}

#[test]
fn test_map_field() {
    let scheme = Scheme! { headers: Map(Bytes) }.build();

    let filter = scheme
        .parse(r#"headers["content-type"] == "text/html""#)
        .unwrap()
        .compile();

    let mut map = TypedMap::<Bytes>::new();
    map.insert(b"content-type".to_vec().into(), Bytes::from("text/html"));
    map.insert(b"host".to_vec().into(), Bytes::from("example.com"));

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("headers").unwrap(), map)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    let filter2 = scheme
        .parse(r#"headers["host"] == "example.org""#)
        .unwrap()
        .compile();
    assert_eq!(filter2.execute(&ctx).unwrap(), false);
}

#[test]
fn test_array_map_each() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("flags", Type::Array(Type::Bool.into())).unwrap();
    builder.add_function("all", AllFunction::default()).unwrap();
    let scheme = builder.build();

    // Pass the Array(Bool) field directly to all() — no [*] needed
    let filter = scheme.parse("all(flags)").unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);

    ctx.set_field_value(
        scheme.get_field("flags").unwrap(),
        Array::from_iter([true, true, true]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("flags").unwrap(),
        Array::from_iter([true, false, true]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 6. 内置函数: all(), any()
// ===========================================================================

#[test]
fn test_all_function() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("results", Type::Array(Type::Bool.into())).unwrap();
    builder.add_function("all", AllFunction::default()).unwrap();
    let scheme = builder.build();

    // all() takes Array(Bool) directly
    let filter = scheme.parse("all(results)").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("results").unwrap(),
        Array::from_iter([true, true]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("results").unwrap(),
        Array::from_iter([true, false]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_any_function() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("results", Type::Array(Type::Bool.into())).unwrap();
    builder.add_function("any", AnyFunction::default()).unwrap();
    let scheme = builder.build();

    // any() takes Array(Bool) directly
    let filter = scheme.parse("any(results)").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(
        scheme.get_field("results").unwrap(),
        Array::from_iter([false, true, false]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(
        scheme.get_field("results").unwrap(),
        Array::from_iter([false, false]),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 7. 自定义函数
// ===========================================================================

fn lowercase<'a>(args: wirefilter::FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let input = args.next()?.ok()?;
    match input {
        LhsValue::Bytes(mut bytes) => {
            if let Bytes::Borrowed(b) = bytes {
                if b.iter().any(u8::is_ascii_uppercase) {
                    bytes.to_mut().make_ascii_lowercase();
                }
            }
            Some(LhsValue::Bytes(bytes))
        }
        _ => None,
    }
}

#[test]
fn test_custom_function() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("host", Type::Bytes).unwrap();
    builder
        .add_function(
            "lowercase",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: SimpleFunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(lowercase),
            },
        )
        .unwrap();
    let scheme = builder.build();

    let filter = scheme
        .parse(r#"lowercase(host) == "example.org""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("host").unwrap(), "EXAMPLE.ORG")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "Example.Org")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("host").unwrap(), "other.com")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 8. List 定义: AlwaysList / NeverList, in $list_name
// ===========================================================================

#[test]
fn test_list_with_always_and_never() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("port", Type::Int).unwrap();
    builder.add_list(Type::Int, AlwaysList {}).unwrap();
    let scheme = builder.build();

    // in $list_name references a named list within the list matcher
    let filter = scheme.parse("port in $even").unwrap().compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("port").unwrap(), 80i64)
        .unwrap();

    // AlwaysList default matcher matches nothing
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 9. 复合表达式: 真实场景组合
// ===========================================================================

#[test]
fn test_http_firewall_rule() {
    let scheme = Scheme! {
        http.method: Bytes,
        http.host: Bytes,
        http.ua: Bytes,
        ip.src: Ip,
        tcp.port: Int,
        ssl: Bool,
    }
    .build();

    // Rule: block non-HTTPS traffic to internal hosts from suspicious UAs
    let filter = scheme
        .parse(
            r#"
            !ssl &&
            http.host contains "internal" &&
            not http.ua ~ "(?i)(googlebot|curl|python)" &&
            tcp.port != 443
        "#,
        )
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // Suspicious: no SSL, internal host, curl UA, non-443 port => matches (block)
    ctx.set_field_value(scheme.get_field("ssl").unwrap(), LhsValue::Bool(false))
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.host").unwrap(), "internal.api.corp")
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.ua").unwrap(), "Mozilla/5.0")
        .unwrap();
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("10.0.0.5").unwrap(),
    )
    .unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 80i64)
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // Legitimate bot => excluded by regex
    ctx.set_field_value(scheme.get_field("http.ua").unwrap(), "Googlebot/2.1")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);

    // HTTPS => excluded
    ctx.set_field_value(scheme.get_field("http.ua").unwrap(), "Mozilla/5.0")
        .unwrap();
    ctx.set_field_value(scheme.get_field("ssl").unwrap(), LhsValue::Bool(true))
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

#[test]
fn test_geoip_filtering() {
    let scheme = Scheme! {
        ip.src: Ip,
        ip.geoip.country: Bytes,
        tcp.port: Int,
    }
    .build();

    let filter = scheme
        .parse(
            r#"ip.src in { 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 } &&
               ip.geoip.country in { "US" "GB" "DE" "FR" "JP" } &&
               tcp.port in { 443 8443 }"#,
        )
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);

    // Internal IP + US + 443 => matches
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("10.0.0.1").unwrap(),
    )
    .unwrap();
    ctx.set_field_value(scheme.get_field("ip.geoip.country").unwrap(), "US")
        .unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 443i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    // External IP => doesn't match
    ctx.set_field_value(
        scheme.get_field("ip.src").unwrap(),
        IpAddr::from_str("8.8.8.8").unwrap(),
    )
    .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}

// ===========================================================================
// 10. SchemeBuilder: 编程式构建 (不用宏)
// ===========================================================================

#[test]
fn test_scheme_builder_programmatic() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("method", Type::Bytes).unwrap();
    builder.add_field("port", Type::Int).unwrap();
    builder.add_field("src_ip", Type::Ip).unwrap();
    builder
        .add_function(
            "lowercase",
            SimpleFunctionDefinition {
                params: vec![SimpleFunctionParam {
                    arg_kind: SimpleFunctionArgKind::Field,
                    val_type: Type::Bytes,
                }],
                opt_params: vec![],
                return_type: Type::Bytes,
                implementation: SimpleFunctionImpl::new(lowercase),
            },
        )
        .unwrap();
    builder.add_list(Type::Int, AlwaysList {}).unwrap();

    let scheme = builder.build();

    let filter = scheme
        .parse(r#"lowercase(method) == "get" && port >= 1024"#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("method").unwrap(), "GET")
        .unwrap();
    ctx.set_field_value(scheme.get_field("port").unwrap(), 8080i64)
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);
}

// ===========================================================================
// 11. 可选字段
// ===========================================================================

#[test]
fn test_optional_field() {
    let mut builder = SchemeBuilder::default();
    builder.add_field("required_field", Type::Int).unwrap();
    builder
        .add_optional_field("optional_field", Type::Bytes)
        .unwrap();
    let scheme = builder.build();

    // Filter referencing the optional field — if it's not set, result is false
    let filter = scheme
        .parse(r#"optional_field == "present""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("required_field").unwrap(), 42i64)
        .unwrap();

    // Optional field not set — filter should evaluate to false (not panic)
    assert_eq!(filter.execute(&ctx).unwrap(), false);

    // Set the optional field
    ctx.set_field_value(scheme.get_field("optional_field").unwrap(), "present")
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);
}

// ===========================================================================
// 12. FilterAst 克隆与重复编译
// ===========================================================================

#[test]
fn test_filter_ast_clone_and_recompile() {
    let scheme = Scheme! { port: Int }.build();
    let ast = scheme.parse("port == 80").unwrap();

    // Clone AST and compile multiple filters from it
    let filter1 = ast.clone().compile();
    let filter2 = ast.compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("port").unwrap(), 80i64)
        .unwrap();
    assert_eq!(filter1.execute(&ctx).unwrap(), true);
    assert_eq!(filter2.execute(&ctx).unwrap(), true);
}

// ===========================================================================
// 13. ExecutionContext 序列化 / 反序列化
// ===========================================================================

#[test]
fn test_execution_context_serde_roundtrip() {
    let scheme = Scheme! {
        port: Int,
        host: Bytes,
        active: Bool,
    }
    .build();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("port").unwrap(), 443i64)
        .unwrap();
    ctx.set_field_value(scheme.get_field("host").unwrap(), "example.com")
        .unwrap();
    ctx.set_field_value(scheme.get_field("active").unwrap(), LhsValue::Bool(true))
        .unwrap();

    // Serialize to JSON
    let json = serde_json::to_string(&ctx).unwrap();

    // Deserialize back using DeserializeSeed trait
    let mut ctx2 = ExecutionContext::<()>::new(&scheme);
    let mut deserializer = serde_json::Deserializer::from_str(&json);
    DeserializeSeed::deserialize(&mut ctx2, &mut deserializer).unwrap();

    assert_eq!(ctx, ctx2);
}

// ===========================================================================
// 14. 用户数据 (user_data)
// ===========================================================================

#[test]
fn test_user_data_in_context() {
    let scheme = Scheme! { port: Int }.build();

    // Create context with custom user data via new_with
    let mut ctx: ExecutionContext<'_, i32> = ExecutionContext::new_with(&scheme, || 42);
    assert_eq!(*ctx.get_user_data(), 42);
    *ctx.get_user_data_mut() = 100;
    assert_eq!(*ctx.get_user_data(), 100);

    ctx.set_field_value(scheme.get_field("port").unwrap(), 80i64)
        .unwrap();

    // Clone the context with () user data so it matches Filter<()> for execution.
    // This preserves all field values while changing the user data type.
    let ctx_unit = ctx.clone_with(());
    let filter = scheme.parse("port == 80").unwrap().compile();
    assert_eq!(filter.execute(&ctx_unit).unwrap(), true);

    // Original context still has its user data
    assert_eq!(*ctx.get_user_data(), 100);
}

// ===========================================================================
// 15. 错误处理: 解析错误、类型不匹配
// ===========================================================================

#[test]
fn test_parse_error_unknown_field() {
    let scheme = Scheme! { port: Int }.build();
    let result = scheme.parse("unknown_field == 42");
    assert!(result.is_err());
}

#[test]
fn test_type_mismatch_on_set() {
    let scheme = Scheme! { port: Int }.build();
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    let result = ctx.set_field_value(scheme.get_field("port").unwrap(), LhsValue::Bool(true));
    assert!(result.is_err());
}

#[test]
fn test_scheme_mismatch_on_set() {
    let scheme1 = Scheme! { port: Int }.build();
    let scheme2 = Scheme! { port: Int }.build();
    let mut ctx = ExecutionContext::<()>::new(&scheme1);
    let result = ctx.set_field_value(scheme2.get_field("port").unwrap(), 80i64);
    assert!(result.is_err());
}

// ===========================================================================
// 16. 二进制字节 (非 UTF-8)
// ===========================================================================

#[test]
fn test_binary_bytes_field() {
    let scheme = Scheme! { raw: Bytes }.build();

    let filter = scheme
        .parse(r#"raw contains "\xff""#)
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme);
    ctx.set_field_value(scheme.get_field("raw").unwrap(), &b"abc\xffdef"[..])
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), true);

    ctx.set_field_value(scheme.get_field("raw").unwrap(), &b"abcdef"[..])
        .unwrap();
    assert_eq!(filter.execute(&ctx).unwrap(), false);
}
