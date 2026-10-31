//! Checks before running (docs/probes.md §6). The console runs them when a probe is written; the sensor runs
//! them again before evaluating, so that a probe that reaches the evaluator has passed them on both sides.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use starlark::syntax::ast::{ArgumentP, AstExpr, AstLiteral, AstStmt, ExprP, StmtP};
use starlark_syntax::syntax::uniplate::Visit;
use starlark::syntax::AstModule;
use starlark::typing::AstModuleTypecheck;

use crate::builtins::globals;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Diagnostic {
    pub span: String,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.span.is_empty() { write!(f, "{}", self.message) } else { write!(f, "{}: {}", self.span, self.message) }
    }
}

pub fn dialect() -> starlark::syntax::Dialect {
    starlark::syntax::Dialect {
        enable_types: starlark::syntax::DialectTypes::Enable,
        ..starlark::syntax::Dialect::Extended
    }
}

/// All diagnostics for one probe; empty means it may run. `tools`: the target sensor's tool names (each is also a
/// function, so a missing one is an unknown name).
pub fn check(name: &str, source: &str, tools: &[String]) -> Vec<Diagnostic> {
    let ast = match AstModule::parse(name, source.to_owned(), &dialect()) {
        Ok(a) => a,
        Err(e) => return vec![from_error(&e)],
    };
    let mut out = Vec::new();
    structure(&ast, &mut out);
    recursion(&ast, &mut out);
    capabilities(&ast, &tools.iter().cloned().collect(), &mut out);
    catalog_entries(&ast, &mut out);
    let (errors, ..) = ast.typecheck(&globals(tools), &HashMap::new());
    out.extend(errors.iter().map(from_error));
    out
}

fn from_error(e: &starlark::Error) -> Diagnostic {
    let span = e.span().map(|s| s.to_string()).unwrap_or_default();
    // The error's own text repeats the location and a source excerpt; keep only the message line.
    let message = format!("{}", e.without_diagnostic());
    Diagnostic { span, message: message.lines().next().unwrap_or("").trim_start_matches("error: ").to_string() }
}

fn top_level(ast: &AstModule) -> Vec<&AstStmt> {
    match &ast.statement().node {
        StmtP::Statements(v) => v.iter().collect(),
        _ => vec![ast.statement()],
    }
}

/// [S2]: the top level only binds constants and defines functions; `main()` exists and takes no arguments.
fn structure(ast: &AstModule, out: &mut Vec<Diagnostic>) {
    let mut has_main = false;
    for (i, stmt) in top_level(ast).into_iter().enumerate() {
        let ok = match &stmt.node {
            StmtP::Def(d) => {
                if d.name.node.ident == "main" {
                    has_main = true;
                    if !d.params.is_empty() {
                        out.push(diag(ast, stmt, "main() must not take arguments"));
                    }
                }
                true
            }
            StmtP::Load(_) | StmtP::Pass => true,
            StmtP::Assign(a) => !contains_call(&a.rhs),
            StmtP::Expression(e) => i == 0 && matches!(&e.node, ExprP::Literal(AstLiteral::String(_))), // docstring
            _ => false,
        };
        if !ok {
            out.push(diag(ast, stmt, "the top level may only define functions and constants; move this into main() (spec [S2])"));
        }
    }
    if !has_main {
        out.push(Diagnostic { span: String::new(), message: "the probe has no main() (spec [S2])".into() });
    }
}

/// No cycle among the probe's functions, counting any reference to a function (a call, or passing it to `each`).
fn recursion(ast: &AstModule, out: &mut Vec<Diagnostic>) {
    let defs: BTreeMap<&str, &AstStmt> = top_level(ast)
        .into_iter()
        .filter_map(|s| match &s.node {
            StmtP::Def(d) => Some((d.name.node.ident.as_str(), s)),
            _ => None,
        })
        .collect();
    let mut edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (name, stmt) in &defs {
        let mut refs = BTreeSet::new();
        walk_stmt(stmt, &mut |e| {
            if let ExprP::Identifier(id) = &e.node {
                if let Some((k, _)) = defs.get_key_value(id.node.ident.as_str()) {
                    refs.insert(*k);
                }
            }
        });
        edges.insert(name, refs);
    }
    // Depth-first search; a back edge is a cycle.
    fn visit<'a>(n: &'a str, edges: &BTreeMap<&'a str, BTreeSet<&'a str>>, path: &mut Vec<&'a str>,
                 done: &mut BTreeSet<&'a str>, found: &mut Vec<Vec<&'a str>>) {
        if let Some(i) = path.iter().position(|p| *p == n) {
            let mut cycle = path[i..].to_vec();
            cycle.push(n);
            found.push(cycle);
            return;
        }
        if !done.insert(n) {
            return;
        }
        path.push(n);
        for m in &edges[n] {
            visit(m, edges, path, done, found);
        }
        path.pop();
    }
    let (mut done, mut found) = (BTreeSet::new(), Vec::new());
    for n in edges.keys() {
        visit(n, &edges, &mut Vec::new(), &mut done, &mut found);
    }
    for cycle in found {
        out.push(diag(ast, defs[cycle[0]], &format!(
            "recursion is not allowed (spec §6): {}", cycle.join(" -> "))));
    }
}

/// Tools named literally in `pipe(["tool", ...], ...)` must exist on the target sensor.
fn capabilities(ast: &AstModule, tools: &BTreeSet<String>, out: &mut Vec<Diagnostic>) {
    walk_stmt(ast.statement(), &mut |e| {
        let ExprP::Call(callee, args) = &e.node else { return };
        if !matches!(&callee.node, ExprP::Identifier(id) if id.node.ident == "pipe") {
            return;
        }
        for a in &args.args {
            let ArgumentP::Positional(stage) = &a.node else { continue };
            let ExprP::List(items) = &stage.node else { continue };
            if let Some(ExprP::Literal(AstLiteral::String(s))) = items.first().map(|x| &x.node) {
                if !tools.contains(&s.node) {
                    out.push(Diagnostic {
                        span: ast.file_span(stage.span).to_string(),
                        message: format!("`{}` is not a tool on the target sensor", s.node),
                    });
                }
            }
        }
    });
}

/// `trace()`'s first argument is a literal naming a catalog entry: the entries a probe uses, and so the capabilities
/// its question needs, are known from its text before it runs (`trace_entries`).
fn catalog_entries(ast: &AstModule, out: &mut Vec<Diagnostic>) {
    walk_stmt(ast.statement(), &mut |e| {
        let ExprP::Call(callee, args) = &e.node else { return };
        if !matches!(&callee.node, ExprP::Identifier(id) if id.node.ident == "trace") {
            return;
        }
        let first = args.args.first().and_then(|a| match &a.node {
            ArgumentP::Positional(x) => Some(x),
            _ => None,
        });
        let message = match first.map(|x| &x.node) {
            Some(ExprP::Literal(AstLiteral::String(s))) if crate::catalog::entry(&s.node).is_some() => return,
            Some(ExprP::Literal(AstLiteral::String(s))) => format!("`{}` is not a catalog entry (entries: {})", s.node,
                crate::catalog::ENTRIES.iter().map(|x| x.name).collect::<Vec<_>>().join(", ")),
            _ => "trace() takes the catalog entry as a literal first argument, trace(\"biolatency\", ...)".into(),
        };
        out.push(Diagnostic { span: ast.file_span(e.span).to_string(), message });
    });
}

/// The catalog entries a probe names in `trace()` calls, sorted; empty if it does not parse.
pub fn trace_entries(source: &str) -> Vec<String> {
    let Ok(ast) = AstModule::parse("probe.star", source.to_owned(), &dialect()) else { return Vec::new() };
    let mut names = BTreeSet::new();
    walk_stmt(ast.statement(), &mut |e| {
        let ExprP::Call(callee, args) = &e.node else { return };
        if !matches!(&callee.node, ExprP::Identifier(id) if id.node.ident == "trace") {
            return;
        }
        if let Some(ArgumentP::Positional(x)) = args.args.first().map(|a| &a.node) {
            if let ExprP::Literal(AstLiteral::String(s)) = &x.node {
                if crate::catalog::entry(&s.node).is_some() {
                    names.insert(s.node.clone());
                }
            }
        }
    });
    names.into_iter().collect()
}

fn diag(ast: &AstModule, stmt: &AstStmt, message: &str) -> Diagnostic {
    Diagnostic { span: ast.file_span(stmt.span).to_string(), message: message.into() }
}

fn contains_call(e: &AstExpr) -> bool {
    let mut found = false;
    walk_expr(e, &mut |x| found |= matches!(x.node, ExprP::Call(..)));
    found
}

fn walk_stmt<'a>(s: &'a AstStmt, f: &mut impl FnMut(&'a AstExpr)) {
    walk(Visit::Stmt(s), f)
}

fn walk_expr<'a>(e: &'a AstExpr, f: &mut impl FnMut(&'a AstExpr)) {
    walk(Visit::Expr(e), f)
}

fn walk<'a>(v: Visit<'a, starlark::syntax::ast::AstNoPayload>, f: &mut impl FnMut(&'a AstExpr)) {
    if let Visit::Expr(e) = &v {
        f(e);
    }
    v.visit_children(|c| walk(c, f));
}
