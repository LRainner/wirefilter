//! 检测结果加白场景：三种 ExecutionContext 使用模式
//!
//! 模式 A: 每次检测 new ctx + set_field_value
//! 模式 B: 复用 ctx + clear + set_field_value
//! 模式 C: 复用 ctx + lazy field/method（推荐）— 注册一次，swap user_data
//!
//! 运行: cargo run --example whitelist_demo

use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{
    AnyFunction, Bytes, DefaultCompiler, ExecutionContext, Filter, FunctionArgs, LhsValue,
    Scheme, SchemeBuilder, SimpleFunctionArgKind, SimpleFunctionParam, Type, TypedArray, TypedMap,
};

// ---------------------------------------------------------------------------
// 1. 定义检测结果结构 + impl 方法
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

// ---------------------------------------------------------------------------
// 2. 构建 Scheme — lazy field/method
// ---------------------------------------------------------------------------

fn build_scheme() -> Scheme {
    let mut builder = SchemeBuilder::default();

    // &str 返回 → add_lazy_field + LhsValue::from (拷贝数据)
    builder.add_lazy_field("attack_type", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.attack_type())).unwrap();
    builder.add_lazy_field("payload", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.payload())).unwrap();
    builder.add_lazy_field("http.method", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.method())).unwrap();
    builder.add_lazy_field("http.path", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.path())).unwrap();
    builder.add_lazy_field("http.body", Type::Bytes, |d: &DetectionResult| LhsValue::from(d.body())).unwrap();

    // 非&str 返回 → add_lazy_field_auto + 方法引用
    builder.add_lazy_field_auto("tcp.port", Type::Int, DetectionResult::tcp_port).unwrap();
    builder.add_lazy_field_auto("ip.src", Type::Ip, DetectionResult::ip_src).unwrap();
    builder.add_lazy_field_auto("ssl", Type::Bool, DetectionResult::ssl).unwrap();

    // 一参 lazy method — header 按 key 取值，调用 det.header(key)，不构建完整 Map！
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

// ---------------------------------------------------------------------------
// 3. 模式 A/B: 手动 set_field_value（传统方式，需构建完整 Map）
// ---------------------------------------------------------------------------

fn build_scheme_set_value() -> Scheme {
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

fn fill_ctx(ctx: &mut ExecutionContext<'static, ()>, scheme: &Scheme, det: &DetectionResult) {
    ctx.set_field_value(scheme.get_field("attack_type").unwrap(), det.attack_type).unwrap();
    ctx.set_field_value(scheme.get_field("payload").unwrap(), det.payload).unwrap();
    ctx.set_field_value(scheme.get_field("http.method").unwrap(), det.method).unwrap();
    ctx.set_field_value(scheme.get_field("http.path").unwrap(), det.path).unwrap();
    let mut header_map = TypedMap::new();
    for (key, values) in &det.headers {
        let mut arr = TypedArray::new();
        for v in values { arr.push(Bytes::from(*v)); }
        header_map.insert(key.as_bytes().to_vec().into_boxed_slice(), arr);
    }
    ctx.set_field_value(scheme.get_field("http.header").unwrap(), LhsValue::Map(header_map.into())).unwrap();
    let mut query_map = TypedMap::new();
    for (key, values) in &det.query {
        let mut arr = TypedArray::new();
        for v in values { arr.push(Bytes::from(*v)); }
        query_map.insert(key.as_bytes().to_vec().into_boxed_slice(), arr);
    }
    ctx.set_field_value(scheme.get_field("http.query").unwrap(), LhsValue::Map(query_map.into())).unwrap();
    ctx.set_field_value(scheme.get_field("http.body").unwrap(), Bytes::from(det.body)).unwrap();
    ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), det.tcp_port).unwrap();
    ctx.set_field_value(scheme.get_field("ip.src").unwrap(), det.ip_src).unwrap();
    ctx.set_field_value(scheme.get_field("ssl").unwrap(), LhsValue::Bool(det.ssl)).unwrap();
}

fn make_detection(attack_type: &'static str, path: &'static str, ssl: bool) -> DetectionResult {
    DetectionResult {
        attack_type,
        payload: r#"<img src=x onerror=alert(1)>"#,
        method: "GET",
        path,
        body: br#"{"event":"user_action"}"#,
        ip_src: IpAddr::from_str("10.0.0.1").unwrap(),
        tcp_port: 80,
        ssl,
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

fn main() {
    // ==================================================================
    // 模式 A: 每次检测 new ctx + set_field_value
    // ==================================================================
    println!("=== 模式 A: 每次检测 new ctx + set_field_value ===");
    let scheme_sv = build_scheme_set_value();
    let rule_sv = r#"attack_type == "xss" && http.path contains "/api/" && any(http.header["user-agent"][*] contains "curl") && !ssl"#;
    let filter_a: Filter<()> = scheme_sv.parse(rule_sv).unwrap().compile();

    {
        let det = make_detection("xss", "/api/v1/users", false);
        let mut ctx = ExecutionContext::<()>::new(&scheme_sv);
        fill_ctx(&mut ctx, &scheme_sv, &det);
        println!("  xss + /api/ + !ssl → {}", if filter_a.execute(&ctx).unwrap() { "命中" } else { "未命中" });
    }
    {
        let det = make_detection("sqli", "/api/v1/users", false);
        let mut ctx = ExecutionContext::<()>::new(&scheme_sv);
        fill_ctx(&mut ctx, &scheme_sv, &det);
        println!("  sqli + /api/ + !ssl → {}", if filter_a.execute(&ctx).unwrap() { "命中" } else { "未命中" });
    }

    // ==================================================================
    // 模式 C: 复用 ctx + lazy field/method（推荐）
    // ==================================================================
    println!("\n=== 模式 C: 复用 ctx + lazy field/method ===");
    let scheme = build_scheme();
    let rule = r#"attack_type() == "xss" && http.path() contains "/api/" && any(http.header("user-agent")[*] contains "curl") && !ssl()"#;
    let filter_c: Filter<DetectionResult> = scheme.parse(rule).unwrap()
        .compile_with_compiler(&mut DefaultCompiler::<DetectionResult>::new());

    {
        let det = make_detection("xss", "/api/v1/users", false);
        let mut ctx = ExecutionContext::new_with(&scheme, || DetectionResult {
            attack_type: "", payload: "", method: "", path: "", body: b"",
            ip_src: IpAddr::from_str("0.0.0.0").unwrap(), tcp_port: 0, ssl: false,
            headers: vec![], query: vec![],
        });

        ctx.update(det);
        println!("  xss + /api/ + !ssl → {}", if filter_c.execute(&ctx).unwrap() { "命中" } else { "未命中" });

        let det = make_detection("sqli", "/api/v1/users", false);
        ctx.update(det);
        println!("  sqli + /api/ + !ssl → {}", if filter_c.execute(&ctx).unwrap() { "命中" } else { "未命中" });
    }

    // ==================================================================
    // 总结
    // ==================================================================
    println!("\n=== 模式 C 优势 ===");
    println!("  - &str 返回: add_lazy_field + LhsValue::from(det.path())");
    println!("  - i64/bool/Ip 返回: add_lazy_field_auto + DetectionResult::method_name");
    println!("  - 一参方法: add_lazy_method + 闭包调用 det.header(key)");
    println!("  - ctx.update(det) 原子完成 clear + swap user_data");
    println!("  - 规则未引用的字段/方法不执行任何计算");
    println!("  - http.header(\"key\") 只构建一个 Array，不构建完整 Map");
}
