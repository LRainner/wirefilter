use std::alloc::System;

#[global_allocator]
static A: System = System;

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{AnyFunction, Bytes, ExecutionContext, LhsValue, Scheme, TypedArray, TypedMap};

// ---------------------------------------------------------------------------
// 模拟检测结果中的 HTTP 解析结构
// ---------------------------------------------------------------------------
// header: Map(Array(Bytes)) — key 是 header name，value 是该 header 的值数组
//   支持重复 header，同一 key 的所有值放入数组
//   例: X-Forwarded-For: 1.1.1.1, 2.2.2.2 → "x-forwarded-for" → ["1.1.1.1", "2.2.2.2"]
//   规则中使用 any(header["key"][*] contains "xxx") 匹配所有值
// query: Map(Array(Bytes)) — key 是参数名，value 是该参数的值数组
//   支持重复 key，同一 key 的所有值放入数组
//   例: ?id=1&id=2 → "id" → ["1", "2"]
//   规则中使用 any(query["key"][*] contains "xxx") 匹配所有值
// ---------------------------------------------------------------------------

fn build_scheme() -> Scheme {
    let mut builder = Scheme! {
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
        // HTTP 头部: Map<Array<Bytes>> — key → value 数组，支持重复 header
        http.header: Map(Array(Bytes)),
        // HTTP query 参数: Map<Array<Bytes>> — key → value 数组，支持重复 key
        http.query: Map(Array(Bytes)),
        // HTTP body
        http.body: Bytes,
        // 网络层
        tcp.port: Int,
        ip.src: Ip,
        ssl: Bool,
    };
    builder.add_function("any", AnyFunction::default()).unwrap();
    builder.build()
}

/// 模拟检测结果
struct DetectionResult {
    attack_type: &'static str,
    payload: &'static str,
    decode_chain: &'static str,
    method: &'static str,
    raw_uri: &'static [u8],
    raw_path: &'static [u8],
    raw_query: &'static [u8],
    path: &'static str,
    filename: &'static str,
    decoded_query: &'static str,
    fragment: &'static [u8],
    body: &'static [u8],
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
        body: br#"{"event":"user_action","timestamp":1713254400,"session_id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","user":{"id":12345,"name":"test_user","email":"test@example.com","roles":["viewer","editor"]},"request":{"method":"POST","path":"/api/v1/data/submit","headers":{"content-type":"application/json","x-request-id":"req-987654321","x-forwarded-for":"192.168.1.100"}},"payload":"%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E","metadata":{"source":"web_client","version":"2.1.0","platform":"linux","browser":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36","extra_fields":{"debug":true,"trace_id":"trace-abc123def456","span_id":"span-789ghi012","environment":"production","deployment":"us-west-2","region":"us-west","availability_zone":"us-west-2a","instance_type":"c5.2xlarge","container_id":"container-xyz789","pod_name":"api-server-7d4f8b6c9-x2k5m","namespace":"production","cluster":"main-cluster","node_name":"node-pool-3-worker-7"}}}"#,
        ip_src: IpAddr::from_str("10.0.0.1").unwrap(),
        tcp_port: 80,
        ssl: false,
    }
}

/// 构建 header Map<Array<Bytes>>，模拟实际 HTTP 解析的 header 结构
/// key 是 header name，value 是该 header 的所有值数组（支持重复 header）
/// 例: X-Forwarded-For: 1.1.1.1, 2.2.2.2 → "x-forwarded-for" → ["1.1.1.1", "2.2.2.2"]
fn build_headers() -> TypedMap<'static, TypedArray<'static, Bytes<'static>>> {
    let mut headers = TypedMap::new();

    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("internal.api.corp"));
        headers.insert(b"host".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("application/json"));
        headers.insert(b"content-type".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("curl/7.68.0"));
        headers.insert(b"user-agent".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("*/*"));
        headers.insert(b"accept".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("req-987654321"));
        headers.insert(b"x-request-id".to_vec().into_boxed_slice(), vals);
    }
    // 重复 header 示例: X-Forwarded-For 有多个值
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("192.168.1.100"));
        vals.push(Bytes::from("10.0.0.1"));
        headers.insert(b"x-forwarded-for".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("session=abc123; lang=en"));
        headers.insert(b"cookie".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"));
        headers.insert(b"authorization".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("856"));
        headers.insert(b"content-length".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from("keep-alive"));
        headers.insert(b"connection".to_vec().into_boxed_slice(), vals);
    }

    headers
}

/// 构建 query Map<Array<Bytes>>，模拟实际 HTTP 解析的 query 结构
/// key 是参数名，value 是该参数的所有值数组（支持重复 key）
/// 例: ?id=1&id=2 → "id" → ["1", "2"]
fn build_query() -> TypedMap<'static, TypedArray<'static, Bytes<'static>>> {
    let mut query = TypedMap::new();

    // id 参数，有重复值
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from(b"\"><script>alert(1)</script>".to_vec().into_boxed_slice()));
        vals.push(Bytes::from(b"normal_value".to_vec().into_boxed_slice()));
        query.insert(b"id".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from(b"1".to_vec().into_boxed_slice()));
        query.insert(b"page".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from(b"20".to_vec().into_boxed_slice()));
        query.insert(b"limit".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from(b"created_at".to_vec().into_boxed_slice()));
        query.insert(b"sort".to_vec().into_boxed_slice(), vals);
    }
    {
        let mut vals = TypedArray::new();
        vals.push(Bytes::from(b"desc".to_vec().into_boxed_slice()));
        query.insert(b"order".to_vec().into_boxed_slice(), vals);
    }

    query
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
    ctx.set_field_value(scheme.get_field("http.header").unwrap(), build_headers()).unwrap();
    ctx.set_field_value(scheme.get_field("http.query").unwrap(), build_query()).unwrap();
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
    let rule = r#"attack_type == "xss" && http.path contains "/api/" && any(http.header["user-agent"][*] contains "curl") && any(http.query["id"][*] contains "script") && !ssl"#;

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

fn generate_100_rules() -> Vec<String> {
    let attack_types = ["sql_injection", "rce", "xxe", "ssrf", "lfi", "rfi", "command_injection", "path_traversal"];
    let paths = ["/admin", "/login", "/api/users", "/upload", "/config", "/debug", "/console", "/graphql"];
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    let uas = ["sqlmap", "nikto", "nmap", "dirbuster", "wfuzz", "gobuster", "masscan", "zgrab"];
    let query_keys = ["id", "page", "limit", "sort", "order"];

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

fn bench_100_rules(c: &mut Criterion) {
    let scheme = build_scheme();
    let det = sample_detection();

    let rules = generate_100_rules();
    let filters: Vec<_> = rules.iter().map(|r| scheme.parse(r).unwrap().compile()).collect();

    // 第 50 条命中
    let mut hit_rules = rules.clone();
    hit_rules[49] = r#"attack_type == "xss" && http.path contains "/api/" && http.method == "GET" && any(http.header["user-agent"][*] contains "curl") && any(http.query["id"][*] contains "script")"#.to_string();
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
