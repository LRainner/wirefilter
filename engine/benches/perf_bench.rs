use std::alloc::System;

#[global_allocator]
static A: System = System;

use criterion::{Criterion, criterion_group, criterion_main};
use std::net::IpAddr;
use std::str::FromStr;
use wirefilter::{ExecutionContext, LhsValue, Scheme};

// ---------------------------------------------------------------------------
// Benchmark 1: Context reuse vs recreation
// ---------------------------------------------------------------------------
// ExecutionContext::new clones the Scheme (Arc::clone, cheap but not free)
// and allocates Box<[Option<LhsValue>>] + Box<[Box<dyn ListMatcher>]>.
// For hot paths, reusing one context with clear() is significantly faster.
// ---------------------------------------------------------------------------

fn bench_context_reuse(c: &mut Criterion) {
    let scheme = Scheme! {
        http.method: Bytes,
        tcp.port: Int,
        ip.src: Ip,
    }
    .build();

    let filter = scheme
        .parse(r#"http.method == "GET" && tcp.port == 443"#)
        .unwrap()
        .compile();

    let mut group = c.benchmark_group("context_lifecycle");

    group.bench_function("recreate_each_time", |b| {
        b.iter(|| {
            let mut ctx = ExecutionContext::<()>::new(&scheme);
            ctx.set_field_value(scheme.get_field("http.method").unwrap(), "GET")
                .unwrap();
            ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 443i64)
                .unwrap();
            filter.execute(&ctx).unwrap();
        });
    });

    group.bench_function("reuse_with_clear", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.clear();
            ctx.set_field_value(scheme.get_field("http.method").unwrap(), "GET")
                .unwrap();
            ctx.set_field_value(scheme.get_field("tcp.port").unwrap(), 443i64)
                .unwrap();
            filter.execute(&ctx).unwrap();
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 2: Execution scaling with filter complexity
// ---------------------------------------------------------------------------
// Each AST node compiles to a Box<dyn Fn>, incurring an indirect call.
// This benchmarks how execution time scales with the number of terms.
// ---------------------------------------------------------------------------

fn bench_execution_complexity(c: &mut Criterion) {
    let scheme = Scheme! {
        f0: Int, f1: Int, f2: Int, f3: Int, f4: Int,
        f5: Int, f6: Int, f7: Int, f8: Int, f9: Int,
    }
    .build();

    let mut group = c.benchmark_group("execution_complexity");

    for n in [1, 4, 8, 10] {
        let terms: Vec<String> = (0..n).map(|i| format!("f{i} == {i}")).collect();
        let filter_str = terms.join(" && ");

        let filter = scheme.parse(&filter_str).unwrap().compile();

        let mut ctx = ExecutionContext::<()>::new(&scheme);
        for i in 0..n {
            let name = format!("f{i}");
            ctx.set_field_value(scheme.get_field(&name).unwrap(), i as i64)
                .unwrap();
        }

        group.bench_function(format!("{}_terms", n), |b| {
            b.iter(|| filter.execute(&ctx).unwrap());
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 3: Parse + compile vs pre-compiled execution
// ---------------------------------------------------------------------------
// Compilation creates boxed closures for every expression node.
// This benchmarks the cost of compilation relative to execution,
// showing why you should compile once and execute many times.
// ---------------------------------------------------------------------------

fn bench_compile_vs_execute(c: &mut Criterion) {
    let scheme = Scheme! {
        ip.src: Ip,
        tcp.port: Int,
        http.host: Bytes,
    }
    .build();

    let filter_str = r#"ip.src == 127.0.0.1 && tcp.port >= 1024 && http.host == "localhost""#;

    let mut group = c.benchmark_group("compile_vs_execute");

    group.bench_function("parse_only", |b| {
        b.iter(|| scheme.parse(filter_str).unwrap());
    });

    group.bench_function("parse_and_compile", |b| {
        b.iter(|| scheme.parse(filter_str).unwrap().compile());
    });

    let filter = scheme.parse(filter_str).unwrap().compile();
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

    group.bench_function("execute_only", |b| {
        b.iter(|| filter.execute(&ctx).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 4: Large `in {}` set — O(n) linear scan for exact values
// ---------------------------------------------------------------------------
// For exact-value sets (Int, Bytes), the list matcher performs a linear scan.
// For CIDR ranges (Ip), it uses RangeSet with binary search O(log n).
// This benchmarks the difference.
// ---------------------------------------------------------------------------

fn bench_large_in_set(c: &mut Criterion) {
    let scheme_int = Scheme! { port: Int }.build();
    let scheme_ip = Scheme! { ip: Ip }.build();

    let mut group = c.benchmark_group("large_in_set");

    // Int: linear scan
    for size in [10, 50, 100, 200] {
        let set: Vec<String> = (1..=size).map(|p| p.to_string()).collect();
        let filter_str = format!("port in {{ {} }}", set.join(" "));
        let filter = scheme_int.parse(&filter_str).unwrap().compile();

        let mut ctx = ExecutionContext::<()>::new(&scheme_int);
        // Match the last element — worst case for linear scan
        ctx.set_field_value(scheme_int.get_field("port").unwrap(), size as i64)
            .unwrap();

        group.bench_function(format!("int_set_{}", size), |b| {
            b.iter(|| filter.execute(&ctx).unwrap());
        });
    }

    // IP CIDR: binary search via RangeSet
    let ip_filter = scheme_ip
        .parse(
            r#"ip in { 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 }"#
        )
        .unwrap()
        .compile();

    let mut ctx = ExecutionContext::<()>::new(&scheme_ip);
    ctx.set_field_value(
        scheme_ip.get_field("ip").unwrap(),
        IpAddr::from_str("173.245.48.1").unwrap(),
    )
    .unwrap();

    group.bench_function("ip_cidr_15_ranges", |b| {
        b.iter(|| ip_filter.execute(&ctx).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 5: AND short-circuit vs XOR full evaluation
// ---------------------------------------------------------------------------
// AND/OR short-circuit: if the first term is false, remaining terms are skipped.
// XOR always evaluates all terms. This benchmarks the difference.
// ---------------------------------------------------------------------------

fn bench_short_circuit(c: &mut Criterion) {
    let scheme = Scheme! {
        a: Bool,
        b: Bool,
        c: Bool,
        d: Bool,
        e: Bool,
    }
    .build();

    let and_filter = scheme.parse("a && b && c && d && e").unwrap().compile();
    let or_filter = scheme.parse("a || b || c || d || e").unwrap().compile();
    let xor_filter = scheme.parse("a ^^ b ^^ c ^^ d ^^ e").unwrap().compile();

    let mut group = c.benchmark_group("short_circuit");

    let mut ctx_false_first = ExecutionContext::<()>::new(&scheme);
    ctx_false_first
        .set_field_value(scheme.get_field("a").unwrap(), LhsValue::Bool(false))
        .unwrap();
    ctx_false_first
        .set_field_value(scheme.get_field("b").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx_false_first
        .set_field_value(scheme.get_field("c").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx_false_first
        .set_field_value(scheme.get_field("d").unwrap(), LhsValue::Bool(true))
        .unwrap();
    ctx_false_first
        .set_field_value(scheme.get_field("e").unwrap(), LhsValue::Bool(true))
        .unwrap();

    let mut ctx_all_true = ExecutionContext::<()>::new(&scheme);
    for name in &["a", "b", "c", "d", "e"] {
        ctx_all_true
            .set_field_value(scheme.get_field(name).unwrap(), LhsValue::Bool(true))
            .unwrap();
    }

    group.bench_function("and_short_circuit_first_false", |b| {
        b.iter(|| and_filter.execute(&ctx_false_first).unwrap());
    });

    group.bench_function("and_all_true_no_short_circuit", |b| {
        b.iter(|| and_filter.execute(&ctx_all_true).unwrap());
    });

    group.bench_function("or_short_circuit_first_true", |b| {
        b.iter(|| or_filter.execute(&ctx_all_true).unwrap());
    });

    group.bench_function("or_all_false_no_short_circuit", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        for name in &["a", "b", "c", "d", "e"] {
            ctx.set_field_value(scheme.get_field(name).unwrap(), LhsValue::Bool(false))
                .unwrap();
        }
        b.iter(|| or_filter.execute(&ctx).unwrap());
    });

    group.bench_function("xor_always_full_eval", |b| {
        b.iter(|| xor_filter.execute(&ctx_all_true).unwrap());
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark 6: set_field_value overhead — type + scheme check each call
// ---------------------------------------------------------------------------

fn bench_set_field_value(c: &mut Criterion) {
    let scheme = Scheme! {
        tcp.port: Int,
        http.host: Bytes,
        ip.src: Ip,
    }
    .build();

    let port_field = scheme.get_field("tcp.port").unwrap();
    let host_field = scheme.get_field("http.host").unwrap();
    let ip_field = scheme.get_field("ip.src").unwrap();

    let mut group = c.benchmark_group("set_field_value");

    group.bench_function("single_int", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.set_field_value(port_field, 443i64).unwrap();
        });
    });

    group.bench_function("single_bytes", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.set_field_value(host_field, "example.com").unwrap();
        });
    });

    group.bench_function("three_fields", |b| {
        let mut ctx = ExecutionContext::<()>::new(&scheme);
        b.iter(|| {
            ctx.set_field_value(port_field, 443i64).unwrap();
            ctx.set_field_value(host_field, "example.com").unwrap();
            ctx.set_field_value(
                ip_field,
                IpAddr::from_str("127.0.0.1").unwrap(),
            )
            .unwrap();
        });
    });

    group.finish();
}

criterion_group! {
    name = perf_benchmarks;
    config = Criterion::default();
    targets =
        bench_context_reuse,
        bench_execution_complexity,
        bench_compile_vs_execute,
        bench_large_in_set,
        bench_short_circuit,
        bench_set_field_value,
}

criterion_main!(perf_benchmarks);
