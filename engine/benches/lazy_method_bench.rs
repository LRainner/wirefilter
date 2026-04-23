use std::alloc::System;

#[global_allocator]
static A: System = System;

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{
    AnyFunction, Bytes, DefaultCompiler, ExecutionContext, Filter, FunctionArgs, LhsValue,
    Scheme, SchemeBuilder, SimpleFunctionArgKind, SimpleFunctionParam, TypedArray, TypedMap, Type,
};

// ---------------------------------------------------------------------------
// 检测结果结构
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
    headers: Vec<(&'static str, Vec<&'static str>)>,
    query: Vec<(&'static str, Vec<&'static str>)>,
}

impl DetectionResult {
    pub fn attack_type(&self) -> &str { self.attack_type }
    pub fn payload(&self) -> &str { self.payload }
    pub fn method(&self) -> &str { self.method }
    pub fn path(&self) -> &str { self.path }
    pub fn body(&self) -> &[u8] { self.body }
    pub fn tcp_port(&self) -> i64 { self.tcp_port }
    pub fn ip_src(&self) -> IpAddr { self.ip_src }
    pub fn ssl(&self) -> bool { self.ssl }

    pub fn header(&self, key: &str) -> Vec<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.iter().map(|s| *s).collect())
            .unwrap_or_default()
    }

    pub fn query(&self, key: &str) -> Vec<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == &key)
            .map(|(_, v)| v.iter().map(|s| *s).collect())
            .unwrap_or_default()
    }
}

fn sample_detection() -> DetectionResult {
    DetectionResult {
        attack_type: "xss",
        payload: r#"<img src=x onerror=alert(1)>"#,
        method: "GET",
        path: "/api/v1/users",
        body: br#"{"event":"user_action"}"#,
        ip_src: IpAddr::from_str("10.0.0.1").unwrap(),
        tcp_port: 80,
        ssl: false,
        headers: vec![
            ("user-agent", vec!["curl/7.68.0"]),
            ("x-forwarded-for", vec!["192.168.1.100", "10.0.0.1"]),
        ],
        query: vec![
            ("id", vec!["><script>alert(1)</script>", "normal_value"]),
            ("page", vec!["1"]),
        ],
    }
}

fn dummy_detection() -> DetectionResult {
    DetectionResult {
        attack_type: "",
        payload: "",
        method: "",
        path: "",
        body: b"",
        ip_src: IpAddr::from_str("0.0.0.0").unwrap(),
        tcp_port: 0,
        ssl: false,
        headers: vec![],
        query: vec![],
    }
}

// ---------------------------------------------------------------------------
// Standard (eager): Scheme! + set_field_value + full Map(Array(Bytes))
// 规则语法: attack_type == "xss" && any(http.header["user-agent"][*] contains "curl")
// ---------------------------------------------------------------------------

fn build_standard_scheme() -> Scheme {
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

fn build_map(entries: &[(&'static str, Vec<&'static str>)]) -> TypedMap<'static, TypedArray<'static, Bytes<'static>>> {
    let mut map = TypedMap::new();
    for (key, values) in entries {
        let mut arr = TypedArray::new();
        for v in values {
            arr.push(Bytes::from(*v));
        }
        map.insert(key.as_bytes().to_vec().into_boxed_slice(), arr);
    }
    map
}

fn fill_standard(ctx: &mut ExecutionContext<'static, ()>, scheme: &Scheme, det: &DetectionResult) {
    ctx.set_field_value(scheme.get_field("attack_type").unwrap(), det.attack_type).unwrap();
    ctx.set_field_value(scheme.get_field("payload").unwrap(), det.payload).unwrap();
    ctx.set_field_value(scheme.get_field("http.method").unwrap(), det.method).unwrap();
    ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path).unwrap();
    ctx.set_field_value(scheme.get_field("http.header").unwrap(), build_map(&det.headers)).unwrap();
    ctx.set_field_value(scheme.get_field("http.query").unwrap(), build_map(&det.query)).unwrap();
    ctx.set_field_value(scheme.get_field("http.body").unwrap(), Bytes::from(det.body)).unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), det.tcp_port).unwrap();
    ctx.set_field_value(scheme.get_field("ip.src").unwrap(), det.ip_src).unwrap();
    ctx.set_field_value(scheme.get_field("ssl").unwrap(), LhsValue::Bool(det.ssl)).unwrap();
}

// ---------------------------------------------------------------------------
// Lazy field/method: add_lazy_field + add_lazy_method + ctx.update(det)
// 规则语法: attack_type() == "xss" && any(http.header("user-agent")[*] contains "curl")
// ---------------------------------------------------------------------------

fn build_lazy_scheme() -> Scheme {
    let mut builder = SchemeBuilder::default();

    // &str 返回 → add_lazy_field + LhsValue::from
    builder.add_lazy_field("attack_type", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.attack_type())).unwrap();
    builder.add_lazy_field("payload", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.payload())).unwrap();
    builder.add_lazy_field("http.method", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.method())).unwrap();
    builder.add_lazy_field("http.path", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.path())).unwrap();
    builder.add_lazy_field("http.body", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.body())).unwrap();

    // 非&str 返回 → add_lazy_field_auto + 方法引用
    builder.add_lazy_field_auto("tcp.port", Type::Int, DetectionResult::tcp_port).unwrap();
    builder.add_lazy_field_auto("ip.src", Type::Ip, DetectionResult::ip_src).unwrap();
    builder.add_lazy_field_auto("ssl", Type::Bool, DetectionResult::ssl).unwrap();

    // 一参 lazy method — header 按 key 取值
    builder.add_lazy_method(
        "http.header",
        vec![SimpleFunctionParam { arg_kind: SimpleFunctionArgKind::Both, val_type: Type::Bytes }],
        Type::Array(Type::Bytes.into()),
        |det: &DetectionResult, args: FunctionArgs| {
            let arg = args.next()?.ok()?;
            let key_bytes = match &arg { LhsValue::Bytes(b) => b, _ => return None };
            let key = std::str::from_utf8(key_bytes.as_ref()).ok()?;
            let mut arr = TypedArray::new();
            for v in det.header(key) { arr.push(Bytes::from(v.to_owned())); }
            Some(LhsValue::Array(arr.into()))
        },
    ).unwrap();

    // 一参 lazy method — query 按 key 取值
    builder.add_lazy_method(
        "http.query",
        vec![SimpleFunctionParam { arg_kind: SimpleFunctionArgKind::Both, val_type: Type::Bytes }],
        Type::Array(Type::Bytes.into()),
        |det: &DetectionResult, args: FunctionArgs| {
            let arg = args.next()?.ok()?;
            let key_bytes = match &arg { LhsValue::Bytes(b) => b, _ => return None };
            let key = std::str::from_utf8(key_bytes.as_ref()).ok()?;
            let mut arr = TypedArray::new();
            for v in det.query(key) { arr.push(Bytes::from(v.to_owned())); }
            Some(LhsValue::Array(arr.into()))
        },
    ).unwrap();

    builder.add_function("any", AnyFunction::default()).unwrap();
    builder.build()
}

// ===========================================================================
// Benchmark 1: 简单字段规则 — 只用 Bytes/Int/Bool，不用 header/query
// 对比 eager 全量填充 vs lazy update (Map 不参与)
// ===========================================================================

fn bench_simple_fields(c: &mut Criterion) {
    let det = sample_detection();

    // Standard
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && http.path contains "/api/" && !ssl"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    // Lazy
    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && http.path() contains "/api/" && !ssl()"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme.parse(lazy_rule).unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("simple_fields");

    group.bench_function("eager_fill_execute_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        b.iter(|| {
            fill_standard(&mut ctx, &std_scheme, &det);
            std_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.bench_function("lazy_update_execute_clear", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
        b.iter(|| {
            ctx.update(sample_detection());
            lazy_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 2: header 规则 — 核心场景
// eager: 构建完整 Map(Array(Bytes)) → any(http.header["user-agent"][*] contains "curl")
// lazy:  只构建一个 key 的 Array → any(http.header("user-agent")[*] contains "curl")
// ===========================================================================

fn bench_header_rule(c: &mut Criterion) {
    let det = sample_detection();

    // Standard
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "curl") && !ssl"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    // Lazy
    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "curl") && !ssl()"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme.parse(lazy_rule).unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("header_rule");

    group.bench_function("eager_fill_execute_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        b.iter(|| {
            fill_standard(&mut ctx, &std_scheme, &det);
            std_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.bench_function("lazy_update_execute_clear", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
        b.iter(|| {
            ctx.update(sample_detection());
            lazy_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 3: header + query 规则 — 两个 Map 字段
// eager: 构建两个完整 Map
// lazy:  各只构建一个 key 的 Array
// ===========================================================================

fn bench_header_and_query(c: &mut Criterion) {
    let det = sample_detection();

    // Standard
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "curl") && any(http.query["id"][*] contains "script") && !ssl"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();

    // Lazy
    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "curl") && any(http.query("id")[*] contains "script") && !ssl()"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme.parse(lazy_rule).unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    let mut group = c.benchmark_group("header_and_query");

    group.bench_function("eager_fill_execute_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        b.iter(|| {
            fill_standard(&mut ctx, &std_scheme, &det);
            std_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.bench_function("lazy_update_execute_clear", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
        b.iter(|| {
            ctx.update(sample_detection());
            lazy_filter.execute(&ctx).unwrap();
            ctx.clear();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 4: fill/update 分离 — 只测填充开销
// ===========================================================================

fn bench_fill_only(c: &mut Criterion) {
    let det = sample_detection();

    let std_scheme = build_standard_scheme();
    let lazy_scheme = build_lazy_scheme();

    let mut group = c.benchmark_group("fill_only");

    group.bench_function("eager_fill_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        b.iter(|| {
            fill_standard(&mut ctx, &std_scheme, &det);
            ctx.clear();
        });
    });

    group.bench_function("lazy_update_clear", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
        b.iter(|| {
            ctx.update(sample_detection());
            ctx.clear();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 5: execute_only — ctx 预填好，只测执行开销
// ===========================================================================

fn bench_execute_only(c: &mut Criterion) {
    let det = sample_detection();

    // Standard
    let std_scheme = build_standard_scheme();
    let std_rule = r#"attack_type == "xss" && any(http.header["user-agent"][*] contains "curl") && !ssl"#;
    let std_filter: Filter<()> = std_scheme.parse(std_rule).unwrap().compile();
    let mut std_ctx = ExecutionContext::<()>::new(&std_scheme);
    fill_standard(&mut std_ctx, &std_scheme, &det);

    // Lazy
    let lazy_scheme = build_lazy_scheme();
    let lazy_rule = r#"attack_type() == "xss" && any(http.header("user-agent")[*] contains "curl") && !ssl()"#;
    let lazy_filter: Filter<DetectionResult> = lazy_scheme.parse(lazy_rule).unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());
    let mut lazy_ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
    lazy_ctx.update(sample_detection());

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
// Benchmark 6: 100 条规则 — eager vs lazy
// ===========================================================================

fn generate_100_rules() -> Vec<String> {
    let attack_types = ["sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi", "command_injection", "path_traversal"];
    let paths = ["/admin", "/login", "/api/users", "/upload", "/config", "/debug", "/console", "/graphql"];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = ["sqlmap", "nikto", "nmap", "dirbuster", "wfuzz", "gobuster", "masscan", "zgrab"];
    let query_keys = ["id", "page"];

    (0..100).map(|i| {
        let at = attack_types[i % attack_types.len()];
        let path = paths[i % paths.len()];
        let method = methods[i % methods.len()];
        let ua = uas[i % uas.len()];
        let qk = query_keys[i % query_keys.len()];
        format!(
            r#"attack_type == "{}" && http.path contains "{}" && http.method == "{}" && any(http.header["user-agent"][*] contains "{}") && any(http.query["{}"][*] contains "evil")"#,
            at, path, method, ua, qk
        )
    }).collect()
}

fn generate_100_lazy_rules() -> Vec<String> {
    let attack_types = ["sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi", "command_injection", "path_traversal"];
    let paths = ["/admin", "/login", "/api/users", "/upload", "/config", "/debug", "/console", "/graphql"];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = ["sqlmap", "nikto", "nmap", "dirbuster", "wfuzz", "gobuster", "masscan", "zgrab"];
    let query_keys = ["id", "page"];

    (0..100).map(|i| {
        let at = attack_types[i % attack_types.len()];
        let path = paths[i % paths.len()];
        let method = methods[i % methods.len()];
        let ua = uas[i % uas.len()];
        let qk = query_keys[i % query_keys.len()];
        format!(
            r#"attack_type() == "{}" && http.path() contains "{}" && http.method() == "{}" && any(http.header("user-agent")[*] contains "{}") && any(http.query("{}")[*] contains "evil")"#,
            at, path, method, ua, qk
        )
    }).collect()
}

fn bench_100_rules(c: &mut Criterion) {
    let det = sample_detection();

    // Standard
    let std_scheme = build_standard_scheme();
    let std_rules = generate_100_rules();
    let std_filters: Vec<_> = std_rules.iter()
        .map(|r| std_scheme.parse(r).unwrap().compile())
        .collect();

    // Lazy
    let lazy_scheme = build_lazy_scheme();
    let lazy_rules = generate_100_lazy_rules();
    let lazy_filters: Vec<_> = lazy_rules.iter()
        .map(|r| lazy_scheme.parse(r).unwrap()
            .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new()))
        .collect();

    let mut group = c.benchmark_group("100_rules");

    group.bench_function("eager_fill_execute_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&std_scheme);
        b.iter(|| {
            fill_standard(&mut ctx, &std_scheme, &det);
            for filter in &std_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
            ctx.clear();
        });
    });

    group.bench_function("lazy_update_execute_clear", |b| {
        let mut ctx = ExecutionContext::new_with(&lazy_scheme, || dummy_detection());
        b.iter(|| {
            ctx.update(sample_detection());
            for filter in &lazy_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
            ctx.clear();
        });
    });

    group.finish();
}

criterion_group! {
    name = lazy_method_benchmarks;
    config = Criterion::default();
    targets =
        bench_simple_fields,
        bench_header_rule,
        bench_header_and_query,
        bench_fill_only,
        bench_execute_only,
        bench_100_rules,
}
criterion_main!(lazy_method_benchmarks);
