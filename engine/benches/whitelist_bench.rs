use std::alloc::System;

#[global_allocator]
static A: System = System;

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{Bytes, ExecutionContext, LhsValue, Scheme};

// ---------------------------------------------------------------------------
// 模拟检测结果中的 HTTP 解析结构
// ---------------------------------------------------------------------------
// 字段来源: 实际 HTTP 解析结果
// attack_type / decode_chain 来自检测引擎
// ---------------------------------------------------------------------------

/// 模拟检测结果
struct DetectionResult {
    attack_type: &'static str,
    payload: &'static str,
    decode_chain: &'static str,
    // HTTP 解析结果字段
    method: &'static str,         // GET / POST / ...
    raw_uri: &'static [u8],      // 未解码 URI
    raw_path: &'static [u8],     // 未解码路径
    raw_query: &'static [u8],    // 未解码 query
    path: &'static str,          // 解码后路径
    filename: &'static str,      // 解码后文件名
    decoded_query: &'static str, // 解码后完整 query
    fragment: &'static [u8],     // URI fragment
    host: &'static str,          // Host header
    content_type: &'static str,  // Content-Type header
    ua: &'static str,            // User-Agent header
    body: &'static [u8],         // 请求 body
    ip_src: IpAddr,
    tcp_port: i64,
    ssl: bool,
}

fn sample_detection() -> DetectionResult {
    DetectionResult {
        attack_type: "xss",
        payload: r#"<img src=x onerror=alert(1)>"#,
        decode_chain: "url_decode.base64_decode",
        method: "GET",
        raw_uri: b"/api/v1/users?id=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
        raw_path: b"/api/v1/users",
        raw_query: b"id=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
        path: "/api/v1/users",
        filename: "users",
        decoded_query: "id=\"><script>alert(1)</script>",
        fragment: b"",
        host: "internal.api.corp",
        content_type: "application/json",
        ua: "curl/7.68.0",
        body: br#"{"event":"user_action","timestamp":1713254400,"session_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","user":{"id":12345,"name":"test_user","email":"test@example.com","roles":["viewer","editor"]},"request":{"method":"POST","path":"/api/v1/data/submit","headers":{"content-type":"application/json","x-request-id":"req-987654321","x-forwarded-for":"192.168.1.100"}},"payload":"%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E","metadata":{"source":"web_client","version":"2.1.0","platform":"linux","browser":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","extra_fields":{"debug":true,"trace_id":"trace-abc123def456","span_id":"span-789ghi012","environment":"production","deployment":"us-west-2","region":"us-west","availability_zone":"us-west-2a","instance_type":"c5.2xlarge","container_id":"container-xyz789","pod_name":"api-server-7d4f8b6c9-x2k5m","namespace":"production","cluster":"main-cluster","node_name":"node-pool-3-worker-7"}}}"#,
        ip_src: IpAddr::from_str("10.0.0.1").unwrap(),
        tcp_port: 80,
        ssl: false,
    }
}

fn build_scheme() -> Scheme {
    Scheme! {
        // 检测结果字段
        attack_type: Bytes,
        payload: Bytes,
        decode_chain: Bytes,
        // HTTP 请求行
        http.method: Bytes,
        http.raw_uri: Bytes,
        http.raw_path: Bytes,
        http.raw_query: Bytes,
        http.path: Bytes,
        http.filename: Bytes,
        http.decoded_query: Bytes,
        http.fragment: Bytes,
        // HTTP 头部
        http.host: Bytes,
        http.content_type: Bytes,
        http.ua: Bytes,
        // HTTP body
        http.body: Bytes,
        // 网络层
        tcp.port: Int,
        ip.src: Ip,
        ssl: Bool,
    }
    .build()
}

/// 把检测结果填入 ExecutionContext
fn fill_ctx(ctx: &mut ExecutionContext<'static, ()>, scheme: &Scheme, det: &DetectionResult) {
    ctx.set_field_value(scheme.get_field("attack_type").unwrap(), det.attack_type).unwrap();
    ctx.set_field_value(scheme.get_field("payload").unwrap(), det.payload).unwrap();
    ctx.set_field_value(scheme.get_field("decode_chain").unwrap(), det.decode_chain).unwrap();
    ctx.set_field_value(scheme.get_field("http.method").unwrap(), det.method).unwrap();
    ctx.set_field_value(scheme.get_field("http.raw_uri").unwrap(), Bytes::from(det.raw_uri)).unwrap();
    ctx.set_field_value(scheme.get_field("http.raw_path").unwrap(), Bytes::from(det.raw_path)).unwrap();
    ctx.set_field_value(scheme.get_field("http.raw_query").unwrap(), Bytes::from(det.raw_query)).unwrap();
    ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path).unwrap();
    ctx.set_field_value(scheme.get_field("http.filename").unwrap(), det.filename).unwrap();
    ctx.set_field_value(scheme.get_field("http.decoded_query").unwrap(), det.decoded_query).unwrap();
    ctx.set_field_value(scheme.get_field("http.fragment").unwrap(), Bytes::from(det.fragment)).unwrap();
    ctx.set_field_value(scheme.get_field("http.host").unwrap(), det.host).unwrap();
    ctx.set_field_value(scheme.get_field("http.content_type").unwrap(), det.content_type).unwrap();
    ctx.set_field_value(scheme.get_field("http.ua").unwrap(), det.ua).unwrap();
    ctx.set_field_value(scheme.get_field("http.body").unwrap(), Bytes::from(det.body)).unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), det.tcp_port).unwrap();
    ctx.set_field_value(scheme.get_field("ip.src").unwrap(), det.ip_src).unwrap();
    ctx.set_field_value(scheme.get_field("ssl").unwrap(), LhsValue::Bool(det.ssl)).unwrap();
}

// ===========================================================================
// Benchmark 1: 各步骤耗时分解
// ===========================================================================

fn bench_step_breakdown(c: &mut Criterion) {
    let scheme = build_scheme();
    let det = sample_detection();
    let rule = r#"attack_type == "xss" && http.path contains "/api/" && http.decoded_query contains "script" && !ssl && http.ua ~ "(curl|python)""#;

    let mut group = c.benchmark_group("step_breakdown");

    group.bench_function("parse", |b| {
        b.iter(|| scheme.parse(rule).unwrap());
    });

    group.bench_function("compile", |b| {
        let ast = scheme.parse(rule).unwrap();
        b.iter(|| ast.clone().compile());
    });

    group.bench_function("new_ctx", |b| {
        b.iter(|| ExecutionContext::<()>::new(&scheme));
    });

    group.bench_function("fill_ctx", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.clear();
            fill_ctx(&mut ctx, &scheme, &det);
        });
    });

    let filter = scheme.parse(rule).unwrap().compile();
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    fill_ctx(&mut ctx, &scheme, &det);

    group.bench_function("execute_only", |b| {
        b.iter(|| filter.execute(&ctx).unwrap());
    });

    group.bench_function("fill_ctx_and_execute", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.clear();
            fill_ctx(&mut ctx, &scheme, &det);
            filter.execute(&ctx).unwrap();
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 2: 100 条规则串行执行
// ===========================================================================
// 100 条规则，每条 5 个条件，测试不同场景

fn generate_100_rules() -> Vec<String> {
    let attack_types = ["sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi", "command_injection", "path_traversal"];
    let paths = ["/admin", "/login", "/api/users", "/upload", "/config", "/debug", "/console", "/graphql"];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = ["sqlmap", "nikto", "nmap", "dirbuster", "wfuzz", "gobuster", "masscan", "zgrab"];
    let content_types = ["multipart/form-data", "application/xml", "text/xml", "application/x-www-form-urlencoded"];

    (0..100).map(|i| {
        let at = attack_types[i % attack_types.len()];
        let path = paths[i % paths.len()];
        let method = methods[i % methods.len()];
        let ua = uas[i % uas.len()];
        let ct = content_types[i % content_types.len()];
        // 5 个条件: attack_type + path + method + ua + content_type
        format!(
            r#"attack_type == "{}" && http.path contains "{}" && http.method == "{}" && http.ua contains "{}" && http.content_type == "{}""#,
            at, path, method, ua, ct
        )
    }).collect()
}

fn bench_100_rules(c: &mut Criterion) {
    let scheme = build_scheme();
    let det = sample_detection();

    let rules = generate_100_rules();
    let filters: Vec<_> = rules.iter().map(|r| scheme.parse(r).unwrap().compile()).collect();

    // 准备一条能在第 50 条命中的规则集
    let mut hit_rules = rules.clone();
    hit_rules[49] = r#"attack_type == "xss" && http.path contains "/api/" && http.method == "GET" && http.ua contains "curl" && http.content_type == "application/json""#.to_string();
    let hit_filters: Vec<_> = hit_rules.iter().map(|r| scheme.parse(r).unwrap().compile()).collect();

    let mut group = c.benchmark_group("100_rules");

    // execute_only: 100 条全部不命中
    let mut ctx = ExecutionContext::<()>::new(&scheme);
    fill_ctx(&mut ctx, &scheme, &det);
    group.bench_function("execute_only_100_miss", |b| {
        b.iter(|| {
            for filter in &filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    // execute_only: 第 50 条命中
    group.bench_function("execute_only_hit_at_50th", |b| {
        b.iter(|| {
            for filter in &hit_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    // fill_ctx + execute: 100 条全部不命中
    group.bench_function("fill_ctx_execute_100_miss", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.clear();
            fill_ctx(&mut ctx, &scheme, &det);
            for filter in &filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    // fill_ctx + execute: 第 50 条命中
    group.bench_function("fill_ctx_execute_hit_at_50th", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.clear();
            fill_ctx(&mut ctx, &scheme, &det);
            for filter in &hit_filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    group.finish();
}

criterion_group! {
    name = whitelist_benchmarks;
    config = Criterion::default();
    targets =
        bench_step_breakdown,
        bench_100_rules,
}

criterion_main!(whitelist_benchmarks);
