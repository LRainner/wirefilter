use std::any::Any;
use std::collections::HashMap;
use std::sync::OnceLock;
use wirefilter::{
    AnyFunction, Bytes, CompoundType, DefaultCompiler, ExecutionContext, LhsValue, Scheme,
    SimpleContextFunctionDefinition, SimpleContextFunctionImpl, TypedArray, TypedMap, Type,
};

fn main() {
    // --- Setup test data ---
    let header_data: HashMap<&[u8], Vec<&[u8]>> = HashMap::from([
        (b"content-type" as &[u8], vec![b"text/html" as &[u8]]),
        (b"host" as &[u8], vec![b"example.com" as &[u8]]),
    ]);

    let query_data: HashMap<&[u8], Vec<&[u8]>> =
        HashMap::from([(b"id" as &[u8], vec![b"42" as &[u8]])]);

    let request_data = RequestData {
        url: b"https://example.com/page?id=42",
        headers: header_data,
        header_map: OnceLock::new(),
        queries: query_data,
        query_map: OnceLock::new(),
    };

    // --- Build scheme ---
    let mut builder = Scheme! {
        http.url: Bytes,
    };

    // Register context-aware functions for lazy data access
    builder
        .add_function(
            "http.header",
            SimpleContextFunctionDefinition {
                params: vec![],
                opt_params: vec![],
                return_type: Type::Map(CompoundType::from_type(Type::Array(Type::Bytes.into()))),
                implementation: SimpleContextFunctionImpl::new(header_fn),
            },
        )
        .unwrap();

    builder
        .add_function(
            "http.query",
            SimpleContextFunctionDefinition {
                params: vec![],
                opt_params: vec![],
                return_type: Type::Map(CompoundType::from_type(Type::Array(Type::Bytes.into()))),
                implementation: SimpleContextFunctionImpl::new(query_fn),
            },
        )
        .unwrap();

    // Register built-in any() function (non-context, works as before)
    builder.add_function("any", AnyFunction::default()).unwrap();

    let scheme = builder.build();

    // --- Compile filter ---
    let filter_expr = r#"http.header()["host"][0] == "example.com" && http.query()["id"][0] == "42""#;
    let ast = scheme.parse(filter_expr).unwrap();
    let mut compiler = DefaultCompiler::<RequestData>::new();
    let filter = ast.compile_with_compiler(&mut compiler);

    // --- Execute with lazy context ---
    let mut ctx = ExecutionContext::new_with(&scheme, || request_data);
    ctx.set_field_value(scheme.get_field("http.url").unwrap(), b"https://example.com/page?id=42")
        .unwrap();

    // http.header() and http.query() lazily build TypedMap on first call
    let result = filter.execute(&ctx).unwrap();
    println!("Filter result: {}", result);

    // --- Second request: different data, maps are rebuilt ---
    let request_data2 = RequestData {
        url: b"https://other.com/",
        headers: HashMap::from([(b"host" as &[u8], vec![b"other.com" as &[u8]])]),
        header_map: OnceLock::new(),
        queries: HashMap::new(),
        query_map: OnceLock::new(),
    };

    let mut ctx2 = ExecutionContext::new_with(&scheme, || request_data2);
    ctx2.set_field_value(scheme.get_field("http.url").unwrap(), b"https://other.com/")
        .unwrap();

    let result2 = filter.execute(&ctx2).unwrap();
    println!("Filter result 2: {}", result2);
}

// --- Request data stored as user_data ---

struct RequestData<'a> {
    url: &'a [u8],
    headers: HashMap<&'a [u8], Vec<&'a [u8]>>,
    header_map: OnceLock<TypedMap<'a, TypedArray<'a, Bytes<'a>>>>,
    queries: HashMap<&'a [u8], Vec<&'a [u8]>>,
    query_map: OnceLock<TypedMap<'a, TypedArray<'a, Bytes<'a>>>>,
}

impl<'a> RequestData<'a> {
    fn get_header_map(&self) -> &TypedMap<'a, TypedArray<'a, Bytes<'a>>> {
        self.header_map.get_or_init(|| {
            let mut map = TypedMap::new();
            for (key, values) in &self.headers {
                let mut arr = TypedArray::new();
                for v in values {
                    arr.push((*v).into());
                }
                map.insert((*key).into(), arr);
            }
            map
        })
    }

    fn get_query_map(&self) -> &TypedMap<'a, TypedArray<'a, Bytes<'a>>> {
        self.query_map.get_or_init(|| {
            let mut map = TypedMap::new();
            for (key, values) in &self.queries {
                let mut arr = TypedArray::new();
                for v in values {
                    arr.push((*v).into());
                }
                map.insert((*key).into(), arr);
            }
            map
        })
    }
}

// --- Context-aware function implementations ---

fn header_fn<'a>(user_data: &dyn Any, _args: wirefilter::FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let request = user_data.downcast_ref::<RequestData<'_>>().expect("user_data must be RequestData");
    Some(LhsValue::Map(request.get_header_map().as_map().into_owned()))
}

fn query_fn<'a>(user_data: &dyn Any, _args: wirefilter::FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let request = user_data.downcast_ref::<RequestData<'_>>().expect("user_data must be RequestData");
    Some(LhsValue::Map(request.get_query_map().as_map().into_owned()))
}
