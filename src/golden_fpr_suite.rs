use crate::config::SpecterConfig;
use crate::differ::{SemverImpact, diff_contracts_with_config};
use crate::extractor::extract_in_memory_files_with_config;

struct GoldenCase {
    name: &'static str,
    base: Vec<(&'static str, &'static str)>,
    head: Vec<(&'static str, &'static str)>,
    config_toml: Option<&'static str>,
}

fn to_owned_files(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(p, c)| ((*p).to_string(), (*c).to_string()))
        .collect()
}

fn build_golden_zero_fpr_corpus() -> Vec<GoldenCase> {
    let mut cases = Vec::with_capacity(110);

    // =========================================================================
    // CATEGORY 1 (12 cases): Rust formatting, comments, whitespace, docstrings
    // =========================================================================
    let rust_fmt_pairs: [(&str, &str, &str); 12] = [
        (
            "rust_fmt_multiline_fn_params",
            "pub fn connect(host: &str, port: u16, tls: bool) -> Result<(), String> { Ok(()) }",
            "pub fn connect(\n    host: &str,\n    port: u16,\n    tls: bool,\n) -> Result<(), String> {\n    Ok(())\n}",
        ),
        (
            "rust_fmt_add_doc_comments",
            "pub fn hash(data: &[u8]) -> u64 { 0 }",
            "/// Computes a fast 64-bit hash.\n/// # Examples\n/// ```\n/// pub fn fake_in_doc() {}\n/// ```\npub fn hash(data: &[u8]) -> u64 { 0 }",
        ),
        (
            "rust_fmt_inner_doc_comments",
            "pub fn init() -> bool { true }",
            "//! Module documentation\n//! pub fn fake_inner_doc() {}\npub fn init() -> bool { true }",
        ),
        (
            "rust_fmt_nested_block_comments",
            "pub fn run(x: i32) -> i32 { x }",
            "/* outer /* nested pub fn fake() {} */ still outer */\npub fn run(x: i32) -> i32 { x }",
        ),
        (
            "rust_fmt_trailing_comma_struct",
            "pub struct Point { pub x: f64, pub y: f64 }",
            "pub struct Point {\n    pub x: f64,\n    pub y: f64,\n}",
        ),
        (
            "rust_fmt_trailing_comma_enum",
            "pub enum Mode { Fast, Safe }",
            "pub enum Mode {\n    Fast,\n    Safe,\n}",
        ),
        (
            "rust_fmt_where_clause_reformat",
            "pub fn sort<T: Ord>(items: &mut [T]) {}",
            "pub fn sort<T>(items: &mut [T])\nwhere\n    T: Ord,\n{\n    items.sort();\n}",
        ),
        (
            "rust_fmt_whitespace_in_generics",
            "pub fn map(m: std::collections::BTreeMap<String, Vec<u8>>) -> Option<usize> { None }",
            "pub fn map(m: std::collections::BTreeMap< String , Vec< u8 > >) -> Option< usize > { None }",
        ),
        (
            "rust_fmt_inline_comments_between_params",
            "pub fn send(a: u32, b: u32) -> bool { true }",
            "pub fn send(\n    a: u32, // timeout\n    b: u32, /* retries */\n) -> bool { true }",
        ),
        (
            "rust_fmt_blank_lines_and_tabs",
            "pub struct A { pub id: u64 }\npub fn get() -> u64 { 1 }",
            "\n\n\tpub struct A {\n\t\tpub id: u64,\n\t}\n\n\n\tpub fn get() -> u64 {\n\t\t1\n\t}\n",
        ),
        (
            "rust_fmt_impl_block_reformat",
            "pub struct S;\nimpl S { pub fn go(&self, x: u8) -> u8 { x } }",
            "pub struct S;\n\nimpl S {\n    /// Runs go.\n    pub fn go(&self, x: u8) -> u8 {\n        x\n    }\n}",
        ),
        (
            "rust_fmt_async_fn_multiline",
            "pub async fn fetch(url: &str) -> Result<String, String> { Ok(url.into()) }",
            "pub async fn fetch(\n    url: &str,\n) -> Result<String, String> {\n    Ok(url.to_string())\n}",
        ),
    ];
    for (name, base, head) in rust_fmt_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/api.rs", base)],
            head: vec![("src/api.rs", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 2 (12 cases): Rust param, lifetime, and generic renames
    // =========================================================================
    let rust_rename_pairs: [(&str, &str, &str); 12] = [
        (
            "rust_rename_single_param",
            "pub fn double(x: i64) -> i64 { x * 2 }",
            "pub fn double(value: i64) -> i64 { value * 2 }",
        ),
        (
            "rust_rename_multi_params",
            "pub fn add(a: i32, b: i32, c: i32) -> i32 { a + b + c }",
            "pub fn add(lhs: i32, rhs: i32, bias: i32) -> i32 { lhs + rhs + bias }",
        ),
        (
            "rust_rename_param_add_mut",
            "pub fn consume(buf: Vec<u8>) -> usize { buf.len() }",
            "pub fn consume(mut data: Vec<u8>) -> usize { data.push(0); data.len() }",
        ),
        (
            "rust_rename_param_underscore",
            "pub fn noop(unused: u32) {}",
            "pub fn noop(_ignored: u32) {}",
        ),
        (
            "rust_rename_single_lifetime",
            "pub fn trim<'a>(s: &'a str) -> &'a str { s.trim() }",
            "pub fn trim<'input>(text: &'input str) -> &'input str { text.trim() }",
        ),
        (
            "rust_rename_two_lifetimes",
            "pub fn pick<'a, 'b>(x: &'a str, y: &'b str) -> &'a str { x }",
            "pub fn pick<'first, 'second>(left: &'first str, right: &'second str) -> &'first str { left }",
        ),
        (
            "rust_rename_single_generic",
            "pub fn identity<T>(v: T) -> T { v }",
            "pub fn identity<Item>(val: Item) -> Item { val }",
        ),
        (
            "rust_rename_two_generics",
            "pub fn pair<K, V>(k: K, v: V) -> (K, V) { (k, v) }",
            "pub fn pair<Key, Val>(key: Key, val: Val) -> (Key, Val) { (key, val) }",
        ),
        (
            "rust_rename_lifetime_and_generics_combined",
            "pub fn parse<'a, T, E>(buf: &'a [u8], f: T) -> Result<&'a str, E> { todo!() }",
            "pub fn parse<'src, F, Err>(input: &'src [u8], handler: F) -> Result<&'src str, Err> { todo!() }",
        ),
        (
            "rust_rename_method_params_and_lifetime",
            "pub struct P;\nimpl P { pub fn slice<'a>(&self, s: &'a str) -> &'a str { s } }",
            "pub struct P;\nimpl P { pub fn slice<'buf>(&self, raw: &'buf str) -> &'buf str { raw } }",
        ),
        (
            "rust_rename_impl_generic_method",
            "pub struct Boxed<T>(T);\nimpl<T> Boxed<T> { pub fn map<U>(&self, x: T, y: U) -> U { y } }",
            "pub struct Boxed<Item>(Item);\nimpl<Item> Boxed<Item> { pub fn map<Out>(&self, a: Item, b: Out) -> Out { b } }",
        ),
        (
            "rust_rename_generic_in_option_result",
            "pub fn wrap<T>(x: Option<T>) -> Result<Option<T>, String> { Ok(x) }",
            "pub fn wrap<Payload>(val: Option<Payload>) -> Result<Option<Payload>, String> { Ok(val) }",
        ),
    ];
    for (name, base, head) in rust_rename_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/api.rs", base)],
            head: vec![("src/api.rs", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 3 (12 cases): Rust attributes (#[derive], #[serde], #[inline], etc.)
    // =========================================================================
    let rust_attr_pairs: [(&str, &str, &str); 12] = [
        (
            "rust_attr_inline_on_fn",
            "pub fn fast(x: u32) -> u32 { x + 1 }",
            "#[inline(always)]\npub fn fast(x: u32) -> u32 { x + 1 }",
        ),
        (
            "rust_attr_must_use_on_fn",
            "pub fn check(v: bool) -> bool { v }",
            "#[must_use = \"check result\"]\npub fn check(v: bool) -> bool { v }",
        ),
        (
            "rust_attr_allow_clippy_on_fn",
            "pub fn compute(a: u64, b: u64) -> u64 { a + b }",
            "#[allow(clippy::too_many_arguments, dead_code)]\npub fn compute(a: u64, b: u64) -> u64 { a + b }",
        ),
        (
            "rust_attr_derive_on_struct",
            "pub struct Config { pub port: u16 }",
            "#[derive(Debug, Clone, PartialEq, Eq)]\npub struct Config { pub port: u16 }",
        ),
        (
            "rust_attr_serde_rename_on_struct_fields",
            "pub struct User { pub id: u64, pub name: String }",
            "pub struct User {\n    #[serde(rename = \"user_id\")]\n    pub id: u64,\n    #[serde(default, alias = \"full_name,display\")]\n    pub name: String,\n}",
        ),
        (
            "rust_attr_serde_on_enum_variants",
            "pub enum Role { Admin, Member }",
            "#[derive(Debug)]\npub enum Role {\n    #[serde(rename = \"admin\")]\n    Admin,\n    #[serde(rename = \"member\")]\n    Member,\n}",
        ),
        (
            "rust_attr_deprecated_on_fn",
            "pub fn old_api(x: i32) -> i32 { x }",
            "#[deprecated(since = \"0.9.0\", note = \"use new_api\")]\npub fn old_api(x: i32) -> i32 { x }",
        ),
        (
            "rust_attr_repr_c_on_struct",
            "pub struct Header { pub magic: u32, pub len: u32 }",
            "#[repr(C)]\npub struct Header { pub magic: u32, pub len: u32 }",
        ),
        (
            "rust_attr_cold_on_method",
            "pub struct Err;\nimpl Err { pub fn format(&self) -> String { String::new() } }",
            "pub struct Err;\nimpl Err { #[cold] #[inline(never)] pub fn format(&self) -> String { String::new() } }",
        ),
        (
            "rust_attr_cfg_attr_on_struct",
            "pub struct Record { pub key: String }",
            "#[cfg_attr(feature = \"serde\", derive(Serialize))]\npub struct Record { pub key: String }",
        ),
        (
            "rust_attr_doc_alias_on_fn",
            "pub fn verify(tok: &str) -> bool { !tok.is_empty() }",
            "#[doc(alias = \"validate\")]\npub fn verify(tok: &str) -> bool { !tok.is_empty() }",
        ),
        (
            "rust_attr_multiple_on_enum",
            "pub enum Level { Info, Warn, Error }",
            "#[derive(Copy, Clone, Debug)]\n#[repr(u8)]\npub enum Level { Info, Warn, Error }",
        ),
    ];
    for (name, base, head) in rust_attr_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/api.rs", base)],
            head: vec![("src/api.rs", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 4 (10 cases): Rust visibility, #[doc(hidden)], #[cfg(test)]
    // =========================================================================
    let rust_vis_pairs: [(&str, &str, &str); 10] = [
        (
            "rust_vis_add_remove_private_fn",
            "pub fn api() -> bool { true }\nfn helper_v1() -> u32 { 1 }",
            "pub fn api() -> bool { true }\nfn helper_v2(x: u32) -> u32 { x }",
        ),
        (
            "rust_vis_add_remove_pub_crate_fn",
            "pub fn api() -> bool { true }\npub(crate) fn internal_old() {}",
            "pub fn api() -> bool { true }\npub(crate) fn internal_new(x: u8) -> u8 { x }",
        ),
        (
            "rust_vis_add_remove_pub_super_fn",
            "pub fn api() -> bool { true }\npub(super) fn parent_only() {}",
            "pub fn api() -> bool { true }",
        ),
        (
            "rust_vis_doc_hidden_fn_removed",
            "pub fn api() -> bool { true }\n#[doc(hidden)]\npub fn __macro_glue() {}",
            "pub fn api() -> bool { true }",
        ),
        (
            "rust_vis_doc_hidden_method_mutated",
            "pub struct S;\nimpl S { pub fn run(&self) {}\n#[doc(hidden)]\npub fn __debug(&self, x: u32) {} }",
            "pub struct S;\nimpl S { pub fn run(&self) {}\n#[doc(hidden)]\npub fn __debug(&self, x: &str) {} }",
        ),
        (
            "rust_vis_doc_hidden_struct_field_removed",
            "pub struct S { pub id: u32, #[doc(hidden)] pub __pad: u8 }",
            "pub struct S { pub id: u32 }",
        ),
        (
            "rust_vis_private_struct_field_changed",
            "pub struct S { pub id: u32, secret: String }",
            "pub struct S { pub id: u32, secret: Vec<u8>, cache: usize }",
        ),
        (
            "rust_vis_cfg_test_at_top_modified",
            "#[cfg(test)]\nmod tests { pub fn t1() {} }\npub fn api() -> bool { true }",
            "#[cfg(test)]\nmod tests { pub fn t2(x: u32) -> u32 { x } }\npub fn api() -> bool { true }",
        ),
        (
            "rust_vis_cfg_test_in_middle_modified",
            "pub fn a() -> u32 { 1 }\n#[cfg(test)]\nmod t { pub fn mock() {} }\npub fn b() -> u32 { 2 }",
            "pub fn a() -> u32 { 1 }\n#[cfg(test)]\nmod t { pub fn mock_v2(x: i32) {} }\npub fn b() -> u32 { 2 }",
        ),
        (
            "rust_vis_private_inline_mod_refactored",
            "mod internal { pub fn x() -> u32 { 1 } }\npub fn api() -> bool { true }",
            "mod internal { pub fn y(s: &str) -> usize { s.len() } }\npub fn api() -> bool { true }",
        ),
    ];
    for (name, base, head) in rust_vis_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/api.rs", base)],
            head: vec![("src/api.rs", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 5 (10 cases): Rust pub use file moves & Logical Symbol IDs
    // =========================================================================
    cases.push(GoldenCase {
        name: "rust_reach_move_fn_between_private_mods",
        base: vec![
            ("src/lib.rs", "mod a;\npub use a::compute;"),
            ("src/a.rs", "pub fn compute(x: u32) -> u32 { x + 1 }"),
        ],
        head: vec![
            ("src/lib.rs", "mod b;\npub use b::compute;"),
            ("src/b.rs", "pub fn compute(n: u32) -> u32 { n + 1 }"),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_move_struct_and_impl_to_subdir",
        base: vec![
            ("src/lib.rs", "mod client;\npub use client::Client;"),
            (
                "src/client.rs",
                "pub struct Client { pub url: String }\nimpl Client { pub fn ping(&self) -> bool { true } }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "mod net;\npub use net::http::Client;"),
            ("src/net/mod.rs", "pub mod http;"),
            (
                "src/net/http.rs",
                "pub struct Client { pub url: String }\nimpl Client { pub fn ping(&self) -> bool { true } }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_private_mod_helper_deleted",
        base: vec![
            ("src/lib.rs", "mod internal;\npub use internal::public_api;"),
            (
                "src/internal.rs",
                "pub fn public_api() -> bool { true }\npub fn private_helper() -> u32 { 1 }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "mod internal;\npub use internal::public_api;"),
            ("src/internal.rs", "pub fn public_api() -> bool { true }"),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_private_mod_helper_signature_changed",
        base: vec![
            ("src/lib.rs", "mod engine;\npub use engine::run;"),
            (
                "src/engine.rs",
                "pub fn run() -> bool { true }\npub fn internal_step(x: u32) -> u32 { x }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "mod engine;\npub use engine::run;"),
            (
                "src/engine.rs",
                "pub fn run() -> bool { true }\npub async fn internal_step(x: &str, y: bool) -> Result<(), String> { Ok(()) }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_mod_rs_to_flat_file",
        base: vec![
            ("src/lib.rs", "pub mod auth;"),
            (
                "src/auth/mod.rs",
                "pub fn verify(tok: &str) -> bool { true }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "pub mod auth;"),
            ("src/auth.rs", "pub fn verify(token: &str) -> bool { true }"),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_flat_file_to_mod_rs",
        base: vec![
            ("src/lib.rs", "pub mod crypto;"),
            (
                "src/crypto.rs",
                "pub fn sign(msg: &[u8]) -> Vec<u8> { vec![] }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "pub mod crypto;"),
            (
                "src/crypto/mod.rs",
                "pub fn sign(payload: &[u8]) -> Vec<u8> { vec![] }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_rename_internal_symbol_keep_pub_use_alias",
        base: vec![
            ("src/lib.rs", "mod v1;\npub use v1::Parser;"),
            ("src/v1.rs", "pub struct Parser { pub strict: bool }"),
        ],
        head: vec![
            ("src/lib.rs", "mod v2;\npub use v2::ParserImpl as Parser;"),
            ("src/v2.rs", "pub struct ParserImpl { pub strict: bool }"),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_glob_reexport_file_move",
        base: vec![
            ("src/lib.rs", "mod core_a;\npub use core_a::*;"),
            (
                "src/core_a.rs",
                "pub fn alpha() -> u8 { 1 }\npub fn beta() -> u8 { 2 }",
            ),
        ],
        head: vec![
            ("src/lib.rs", "mod core_b;\npub use core_b::*;"),
            (
                "src/core_b.rs",
                "pub fn alpha() -> u8 { 1 }\npub fn beta() -> u8 { 2 }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_unreferenced_orphan_file_deleted",
        base: vec![
            ("src/lib.rs", "pub fn root() -> bool { true }"),
            ("src/orphan.rs", "pub fn dead_code() -> bool { false }"),
        ],
        head: vec![("src/lib.rs", "pub fn root() -> bool { true }")],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "rust_reach_custom_cargo_lib_path",
        base: vec![
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[lib]\npath = \"lib/entry.rs\"",
            ),
            ("lib/entry.rs", "pub fn entry(x: i32) -> i32 { x }"),
            ("lib/unused.rs", "pub fn unused_fn() {}"),
        ],
        head: vec![
            (
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[lib]\npath = \"lib/entry.rs\"",
            ),
            ("lib/entry.rs", "pub fn entry(val: i32) -> i32 { val * 1 }"),
        ],
        config_toml: None,
    });

    // =========================================================================
    // CATEGORY 6 (8 cases): Rust const values, body refactors, raw strings, chars
    // =========================================================================
    let rust_body_pairs: [(&str, &str, &str); 8] = [
        (
            "rust_const_str_value_change",
            "pub const VERSION: &str = \"0.9.0\";",
            "pub const VERSION: &str = \"1.0.0\";",
        ),
        (
            "rust_const_usize_value_change",
            "pub const MAX_BUFFER: usize = 1024;",
            "pub const MAX_BUFFER: usize = 4096;",
        ),
        (
            "rust_body_algorithm_rewrite",
            "pub fn fib(n: u64) -> u64 { if n < 2 { n } else { fib(n-1) + fib(n-2) } }",
            "pub fn fib(n: u64) -> u64 { let (mut a, mut b) = (0, 1); for _ in 0..n { (a, b) = (b, a + b); } a }",
        ),
        (
            "rust_raw_string_with_fake_pub_fn",
            "pub fn template() -> &'static str { \"hello\" }",
            "pub fn template() -> &'static str { r#\"\npub fn fake_fn(x: u32) -> u32 { x }\n\"# }",
        ),
        (
            "rust_raw_string_multi_hash",
            "pub fn doc() -> &'static str { \"\" }",
            "pub fn doc() -> &'static str { r###\"pub struct Fake { pub a: u8 }\"### }",
        ),
        (
            "rust_char_literal_quotes_in_body",
            "pub fn is_quote(c: char) -> bool { c == '\"' }",
            "pub fn is_quote(c: char) -> bool { c == '\"' || c == '\\'' }",
        ),
        (
            "rust_inner_closure_and_local_struct",
            "pub fn process(x: i32) -> i32 { x }",
            "pub fn process(x: i32) -> i32 {\n    struct Local { v: i32 }\n    let f = |n: i32| n + 1;\n    f(Local { v: x }.v)\n}",
        ),
        (
            "rust_static_lifetime_preserved",
            "pub fn tag() -> &'static str { \"v1\" }",
            "pub fn tag() -> &'static str { \"v2\" }",
        ),
    ];
    for (name, base, head) in rust_body_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/api.rs", base)],
            head: vec![("src/api.rs", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 7 (8 cases): TypeScript formatting, comments, JSDoc, const values
    // =========================================================================
    let ts_fmt_pairs: [(&str, &str, &str); 8] = [
        (
            "ts_fmt_multiline_function",
            "export function greet(name: string, polite?: boolean): string { return name; }",
            "export function greet(\n  name: string,\n  polite?: boolean,\n): string {\n  return polite ? `Hello, ${name}` : name;\n}",
        ),
        (
            "ts_fmt_add_jsdoc",
            "export function parse(raw: string): number { return Number(raw); }",
            "/**\n * Parses a numeric string.\n * @param raw input\n */\nexport function parse(raw: string): number { return Number(raw); }",
        ),
        (
            "ts_fmt_interface_semicolons_and_spaces",
            "export interface Opts { host: string; port?: number; }",
            "export interface Opts {\n  host:   string;\n  port?:  number;\n}",
        ),
        (
            "ts_fmt_const_untyped_value_bump",
            "export const SDK_VERSION = \"0.9.0\";",
            "export const SDK_VERSION = \"1.0.0\";",
        ),
        (
            "ts_fmt_const_typed_value_bump",
            "export const DEFAULT_TIMEOUT_MS: number = 3000;",
            "export const DEFAULT_TIMEOUT_MS: number = 5000;",
        ),
        (
            "ts_fmt_enum_value_change",
            "export enum Color { Red = 'red', Blue = 'blue' }",
            "export enum Color {\n  Red = '#ff0000',\n  Blue = '#0000ff',\n}",
        ),
        (
            "ts_fmt_private_class_members_refactored",
            "export class Svc { private state: number = 0; public run(): boolean { return true; } }",
            "export class Svc { private cache: Map<string, number> = new Map(); #secret = 1; protected helper() {} public run(): boolean { return true; } }",
        ),
        (
            "ts_fmt_nested_helpers_inside_class_method",
            "export class Api { public handle(x: string): number { return x.length; } }",
            "export class Api {\n  public handle(x: string): number {\n    function inner(s: string) { return s.trim(); }\n    const obj = { nested(v: number) { return v; } };\n    return obj.nested(inner(x).length);\n  }\n}",
        ),
    ];
    for (name, base, head) in ts_fmt_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/mod.ts", base)],
            head: vec![("src/mod.ts", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 8 (10 cases): TypeScript unions, Array<T>, generics, param renames
    // =========================================================================
    let ts_canon_pairs: [(&str, &str, &str); 10] = [
        (
            "ts_canon_union_order_param",
            "export function fmt(x: string | number): string { return String(x); }",
            "export function fmt(x: number | string): string { return String(x); }",
        ),
        (
            "ts_canon_union_order_three_members",
            "export type Val = string | number | boolean;",
            "export type Val = boolean | string | number;",
        ),
        (
            "ts_canon_array_generic_vs_brackets",
            "export function sum(nums: Array<number>): number { return 0; }",
            "export function sum(nums: number[]): number { return 0; }",
        ),
        (
            "ts_canon_array_of_union",
            "export function list(xs: Array<string | number>): Array<number | string> { return xs; }",
            "export function list(xs: (number | string)[]): (string | number)[] { return xs; }",
        ),
        (
            "ts_canon_promise_of_array",
            "export async function load(): Promise<Array<string>> { return []; }",
            "export async function load(): Promise<string[]> { return []; }",
        ),
        (
            "ts_canon_generic_rename_single",
            "export function wrap<T>(x: T): Array<T> { return [x]; }",
            "export function wrap<Item>(val: Item): Item[] { return [val]; }",
        ),
        (
            "ts_canon_generic_rename_pair",
            "export function map<K, V>(k: K, v: V): Map<K, V> { return new Map(); }",
            "export function map<Key, Value>(key: Key, value: Value): Map<Key, Value> { return new Map(); }",
        ),
        (
            "ts_canon_param_rename",
            "export function connect(host: string, port: number): boolean { return true; }",
            "export function connect(hostname: string, tcpPort: number): boolean { return true; }",
        ),
        (
            "ts_canon_interface_field_union_order",
            "export interface Node { id: string | number; tags: Array<string>; }",
            "export interface Node { id: number | string; tags: string[]; }",
        ),
        (
            "ts_canon_arrow_generic_and_union",
            "export const pick = <T>(xs: Array<T>, id: string | number): T => xs[0];",
            "export const pick = <Item>(list: Item[], key: number | string): Item => list[0];",
        ),
    ];
    for (name, base, head) in ts_canon_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/mod.ts", base)],
            head: vec![("src/mod.ts", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 9 (8 cases): TypeScript @internal / @private JSDoc exclusions
    // =========================================================================
    let ts_internal_pairs: [(&str, &str, &str); 8] = [
        (
            "ts_internal_fn_removed",
            "export function pubApi(): void {}\n/** @internal */\nexport function _priv(): void {}",
            "export function pubApi(): void {}",
        ),
        (
            "ts_private_fn_signature_changed",
            "export function pubApi(): void {}\n/** @private */\nexport function _boot(a: string): void {}",
            "export function pubApi(): void {}\n/** @private */\nexport function _boot(a: number, b: boolean): string { return ''; }",
        ),
        (
            "ts_internal_arrow_removed",
            "export const pub = (): number => 1;\n/** @internal */\nexport const _secret = (x: number): number => x;",
            "export const pub = (): number => 1;",
        ),
        (
            "ts_internal_class_method_removed",
            "export class C { public ok(): void {}\n/** @internal */\npublic _reset(): void {} }",
            "export class C { public ok(): void {} }",
        ),
        (
            "ts_internal_class_prop_removed",
            "export class C { public id: string;\n/** @internal */\npublic _debug: boolean; }",
            "export class C { public id: string; }",
        ),
        (
            "ts_internal_interface_field_removed",
            "export interface I { id: string;\n/** @internal */\n_meta: string; }",
            "export interface I { id: string; }",
        ),
        (
            "ts_internal_const_removed",
            "export const PUB: number = 1;\n// @internal\nexport const INTERNAL_KEY: string = 'x';",
            "export const PUB: number = 1;",
        ),
        (
            "ts_internal_with_decorator",
            "export class C { public ok(): void {} }\n/** @internal */\n@deprecated\nexport class InternalRunner { public run(): void {} }",
            "export class C { public ok(): void {} }",
        ),
    ];
    for (name, base, head) in ts_internal_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/mod.ts", base)],
            head: vec![("src/mod.ts", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 10 (6 cases): TypeScript return covariance & arrow/fn equivalence
    // =========================================================================
    let ts_variance_pairs: [(&str, &str, &str); 6] = [
        (
            "ts_covariant_return_narrow_2_to_1",
            "export function parse(): string | number { return 'a'; }",
            "export function parse(): string { return 'a'; }",
        ),
        (
            "ts_covariant_return_narrow_3_to_2",
            "export function parse(): string | number | boolean { return 'a'; }",
            "export function parse(): number | string { return 'a'; }",
        ),
        (
            "ts_covariant_method_return_narrow",
            "export class C { public get(): string | null { return null; } }",
            "export class C { public get(): string { return ''; } }",
        ),
        (
            "ts_arrow_to_function_declaration",
            "export const ping = async (url: string): Promise<boolean> => true;",
            "export async function ping(endpoint: string): Promise<boolean> { return true; }",
        ),
        (
            "ts_function_expr_to_arrow",
            "export const calc = function(a: number, b: number): number { return a + b; };",
            "export const calc = (x: number, y: number): number => x + y;",
        ),
        (
            "ts_class_decorators_added",
            "export class Worker { public run(job: string): void {} }",
            "@injectable\nexport class Worker { @trace\npublic run(task: string): void {} }",
        ),
    ];
    for (name, base, head) in ts_variance_pairs {
        cases.push(GoldenCase {
            name,
            base: vec![("src/mod.ts", base)],
            head: vec![("src/mod.ts", head)],
            config_toml: None,
        });
    }

    // =========================================================================
    // CATEGORY 11 (5 cases): TS/Deno entry-point reachability & file moves
    // =========================================================================
    cases.push(GoldenCase {
        name: "ts_reach_pkg_json_file_move_fn",
        base: vec![
            ("package.json", r#"{"exports": {".": "./src/index.ts"}}"#),
            ("src/index.ts", r#"export { hash } from "./a.ts";"#),
            (
                "src/a.ts",
                "export function hash(s: string): string { return s; }",
            ),
        ],
        head: vec![
            ("package.json", r#"{"exports": {".": "./src/index.ts"}}"#),
            (
                "src/index.ts",
                r#"export { hash } from "./crypto/hash.ts";"#,
            ),
            (
                "src/crypto/hash.ts",
                "export function hash(input: string): string { return input; }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "ts_reach_pkg_json_internal_file_deleted",
        base: vec![
            ("package.json", r#"{"main": "./src/index.ts"}"#),
            (
                "src/index.ts",
                "export function ok(): boolean { return true; }",
            ),
            ("src/internal/dead.ts", "export function dead(): void {}"),
        ],
        head: vec![
            ("package.json", r#"{"main": "./src/index.ts"}"#),
            (
                "src/index.ts",
                "export function ok(): boolean { return true; }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "ts_reach_pkg_json_star_reexport_move",
        base: vec![
            ("package.json", r#"{"exports": "./src/index.ts"}"#),
            ("src/index.ts", r#"export * from "./old_utils.ts";"#),
            (
                "src/old_utils.ts",
                "export function trim(s: string): string { return s.trim(); }",
            ),
        ],
        head: vec![
            ("package.json", r#"{"exports": "./src/index.ts"}"#),
            ("src/index.ts", r#"export * from "./utils/str.ts";"#),
            (
                "src/utils/str.ts",
                "export function trim(v: string): string { return v.trim(); }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "ts_reach_deno_json_subpath_move",
        base: vec![
            (
                "deno.json",
                r#"{"exports": {".": "./mod.ts", "./net": "./net.ts"}}"#,
            ),
            ("mod.ts", "export function boot(): void {}"),
            ("net.ts", r#"export { dial } from "./v1_dial.ts";"#),
            (
                "v1_dial.ts",
                "export function dial(addr: string): boolean { return true; }",
            ),
        ],
        head: vec![
            (
                "deno.json",
                r#"{"exports": {".": "./mod.ts", "./net": "./net.ts"}}"#,
            ),
            ("mod.ts", "export function boot(): void {}"),
            ("net.ts", r#"export { dial } from "./tcp/dial.ts";"#),
            (
                "tcp/dial.ts",
                "export function dial(host: string): boolean { return true; }",
            ),
        ],
        config_toml: None,
    });
    cases.push(GoldenCase {
        name: "ts_reach_pkg_json_conditional_import_export",
        base: vec![
            (
                "package.json",
                r#"{"exports": {".": {"import": "./src/index.ts"}}}"#,
            ),
            (
                "src/index.ts",
                "export function run(x: number): number { return x; }",
            ),
            (
                "src/bench_helper.ts",
                "export function benchOnly(): void {}",
            ),
        ],
        head: vec![
            (
                "package.json",
                r#"{"exports": {".": {"import": "./src/index.ts"}}}"#,
            ),
            (
                "src/index.ts",
                "export function run(n: number): number { return n; }",
            ),
        ],
        config_toml: None,
    });

    // =========================================================================
    // CATEGORY 12 (4 cases): specter.toml config & inline suppressions
    // =========================================================================
    cases.push(GoldenCase {
        name: "cfg_ignore_paths_glob",
        base: vec![
            ("src/api.rs", "pub fn ok() -> bool { true }"),
            (
                "src/generated/proto.rs",
                "pub fn old_proto(x: u32) -> u32 { x }",
            ),
        ],
        head: vec![("src/api.rs", "pub fn ok() -> bool { true }")],
        config_toml: Some("ignore_paths = [\"src/generated/**\"]"),
    });
    cases.push(GoldenCase {
        name: "cfg_ignore_symbols_wildcard",
        base: vec![(
            "src/api.rs",
            "pub fn ok() -> bool { true }\npub fn debug_trace() {}",
        )],
        head: vec![("src/api.rs", "pub fn ok() -> bool { true }")],
        config_toml: Some("ignore_symbols = [\"debug_*\"]"),
    });
    cases.push(GoldenCase {
        name: "cfg_rule_severity_off",
        base: vec![("src/api.rs", "pub fn a() -> bool { true }")],
        head: vec![(
            "src/api.rs",
            "pub fn a() -> bool { true }\npub fn b() -> bool { true }",
        )],
        config_toml: Some("[rule_severity]\nSPC011 = \"off\""),
    });
    cases.push(GoldenCase {
        name: "inline_suppression_with_valid_reason",
        base: vec![("src/api.rs", "pub fn connect(port: u16) -> bool { true }")],
        head: vec![(
            "src/api.rs",
            "// specter-ignore: SPC005 -- migrated to u32 port range per RFC-42\npub fn connect(port: u32) -> bool { true }",
        )],
        config_toml: None,
    });

    cases
}

#[test]
fn test_40_golden_100_plus_zero_false_positive_regression_gate() {
    let corpus = build_golden_zero_fpr_corpus();
    assert!(
        corpus.len() >= 100,
        "Golden FPR corpus must contain at least 100 real-world safe refactoring cases, found {}",
        corpus.len()
    );

    let mut false_positives = Vec::new();

    for case in &corpus {
        let cfg = match case.config_toml {
            Some(raw) => SpecterConfig::parse_toml(raw)
                .unwrap_or_else(|e| panic!("Invalid TOML in golden case `{}`: {}", case.name, e)),
            None => SpecterConfig::default(),
        };

        let base_snap = extract_in_memory_files_with_config(&to_owned_files(&case.base), &cfg);
        let head_snap = extract_in_memory_files_with_config(&to_owned_files(&case.head), &cfg);
        let diff = diff_contracts_with_config(&base_snap, &head_snap, &cfg);

        if diff.breaking_count > 0 || diff.required_bump != SemverImpact::Patch {
            false_positives.push(format!(
                "- `{}`: bump={:?}, breaking={}, findings={:?}",
                case.name, diff.required_bump, diff.breaking_count, diff.findings
            ));
        }
    }

    assert!(
        false_positives.is_empty(),
        "0% FPR GATE VIOLATED! {} / {} cases produced false positives:\n{}",
        false_positives.len(),
        corpus.len(),
        false_positives.join("\n")
    );
}
