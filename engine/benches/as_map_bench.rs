use criterion::{Criterion, criterion_group, criterion_main};
use wirefilter::{AnyFunction, Bytes, ExecutionContext, Filter, TypedArray, TypedMap};

// ---------------------------------------------------------------------------
// DetectionResult — 模拟 WAF 解析结果
// ---------------------------------------------------------------------------

struct DetectionResult<'a> {
    path: &'a [u8],
    headers: TypedMap<'a, TypedArray<'a, Bytes<'a>>>,
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

fn sample_detection() -> DetectionResult<'static> {
    DetectionResult {
        path: b"/api/v2/users/12345/settings?tab=security&section=2fa&action=enable",
        headers: build_headers(),
    }
}

// ---------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------

fn build_scheme() -> wirefilter::Scheme {
    use wirefilter::Scheme;
    let mut builder = Scheme! {
        http.path: Bytes,
        http.header: Map(Array(Bytes)),
    };
    builder.add_function("any", AnyFunction::default()).unwrap();
    builder.build()
}

// ===========================================================================
// Benchmark 1: 新请求 — 每次新建 context + fill + execute
// 数据在循环外构造
// eager_owned: 预转 Map，循环内 .clone() (BTreeMap 深拷贝)
// eager_borrow: 循环内 .as_map() (零拷贝引用)
// ===========================================================================

fn bench_new_request(c: &mut Criterion) {
    let scheme = build_scheme();
    let rule = r#"any(http.header["user-agent"][*] contains "Chrome")"#;
    let filter: Filter<()> = scheme.parse(rule).unwrap().compile();

    let mut group = c.benchmark_group("new_request");

    group.bench_function("eager_owned", |b| {
        let det = sample_detection();
        let header_map = wirefilter::Map::from(det.headers);
        b.iter(|| {
            let mut ctx = ExecutionContext::new(&scheme);
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), header_map.clone())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.bench_function("eager_borrow", |b| {
        let det = sample_detection();
        b.iter(|| {
            let mut ctx = ExecutionContext::new(&scheme);
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), det.headers.as_map())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 2: 重用 context — clear + fill + execute
// ===========================================================================

fn bench_reuse_context(c: &mut Criterion) {
    let scheme = build_scheme();
    let rule = r#"any(http.header["user-agent"][*] contains "Chrome")"#;
    let filter: Filter<()> = scheme.parse(rule).unwrap().compile();

    let mut group = c.benchmark_group("reuse_context");

    group.bench_function("eager_owned", |b| {
        let det = sample_detection();
        let header_map = wirefilter::Map::from(det.headers);
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), header_map.clone())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.bench_function("eager_borrow", |b| {
        let det = sample_detection();
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), det.headers.as_map())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 3: 100 条规则 — 重用 context + 多规则执行
// ===========================================================================

fn bench_reuse_100_rules(c: &mut Criterion) {
    let scheme = build_scheme();
    let rules: Vec<String> = (0..100).map(|i| {
        let paths = ["/admin", "/login", "/api/users", "/upload", "/config", "/debug", "/console", "/graphql"];
        let uas = ["sqlmap", "nikto", "nmap", "dirbuster", "wfuzz", "gobuster", "masscan", "zgrab"];
        format!(
            r#"http.path contains "{}" && any(http.header["user-agent"][*] contains "{}")"#,
            paths[i % 8], uas[i % 8]
        )
    }).collect();
    let filters: Vec<_> = rules.iter()
        .map(|r| scheme.parse(r).unwrap().compile())
        .collect();

    let mut group = c.benchmark_group("reuse_100_rules");

    group.bench_function("eager_owned", |b| {
        let det = sample_detection();
        let header_map = wirefilter::Map::from(det.headers);
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), header_map.clone())
                .unwrap();
            for filter in &filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    group.bench_function("eager_borrow", |b| {
        let det = sample_detection();
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), det.headers.as_map())
                .unwrap();
            for filter in &filters {
                if filter.execute(&ctx).unwrap() {
                    break;
                }
            }
        });
    });

    group.finish();
}

// ===========================================================================
// Benchmark 4: 纯执行开销 — context 预填好，只测 execute
// ===========================================================================

fn bench_execute_only(c: &mut Criterion) {
    let scheme = build_scheme();
    let rule = r#"any(http.header["user-agent"][*] contains "Chrome")"#;
    let filter: Filter<()> = scheme.parse(rule).unwrap().compile();

    let mut group = c.benchmark_group("execute_only");

    {
        let det = sample_detection();
        let header_map = wirefilter::Map::from(det.headers);
        let mut ctx = ExecutionContext::new(&scheme);
        ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
            .unwrap();
        ctx.set_field_value(scheme.get_field("http.header").unwrap(), header_map)
            .unwrap();
        group.bench_function("eager_owned", |b| {
            b.iter(|| filter.execute(&ctx).unwrap());
        });
    }

    {
        let det = sample_detection();
        let mut ctx = ExecutionContext::new(&scheme);
        ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
            .unwrap();
        ctx.set_field_value(scheme.get_field("http.header").unwrap(), det.headers.as_map())
            .unwrap();
        group.bench_function("eager_borrow", |b| {
            b.iter(|| filter.execute(&ctx).unwrap());
        });
    }

    group.finish();
}

// ===========================================================================
// Benchmark 5: 短路求值 — 第一个条件不满足，Map 未被访问
// ===========================================================================

fn bench_short_circuit(c: &mut Criterion) {
    let scheme = build_scheme();
    let rule = r#"http.path == "nonexistent" && any(http.header["user-agent"][*] contains "Chrome")"#;
    let filter: Filter<()> = scheme.parse(rule).unwrap().compile();

    let mut group = c.benchmark_group("short_circuit");

    group.bench_function("eager_owned", |b| {
        let det = sample_detection();
        let header_map = wirefilter::Map::from(det.headers);
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), header_map.clone())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.bench_function("eager_borrow", |b| {
        let det = sample_detection();
        let mut ctx = ExecutionContext::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path)
                .unwrap();
            ctx.set_field_value(scheme.get_field("http.header").unwrap(), det.headers.as_map())
                .unwrap();
            filter.execute(&ctx).unwrap()
        });
    });

    group.finish();
}

criterion_group! {
    name = as_map_benchmarks;
    config = Criterion::default();
    targets =
        bench_new_request,
        bench_reuse_context,
        bench_reuse_100_rules,
        bench_execute_only,
        bench_short_circuit
}
criterion_main!(as_map_benchmarks);
