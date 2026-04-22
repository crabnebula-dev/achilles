//! AST helpers for JS/TS rules.
//!
//! Uses [`oxc_parser`] + [`oxc_ast_visit`]. Rules are expressed as functions
//! of `&Program` → `Vec<AstMatch>`; each match carries a byte span so the
//! scanner can compute line/column and extract a sample from the original
//! source.

use oxc_ast::ast::{
    Argument, CallExpression, Expression, ObjectExpression, ObjectProperty, ObjectPropertyKind,
    Program, PropertyKey,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::Span;

/// One hit from a walker: the source byte range and an optional extra note.
#[derive(Debug, Clone)]
pub struct AstMatch {
    pub span: Span,
    pub note: &'static str,
}

impl AstMatch {
    pub fn new(span: Span, note: &'static str) -> Self {
        Self { span, note }
    }
}

/// Parse `source` and run every AST rule's walker, returning the merged set
/// of matches. `source_type` is inferred from the file extension by the
/// caller via [`oxc_span::SourceType::from_path`].
///
/// A parse error doesn't abort the scan — oxc returns a partial AST plus a
/// list of diagnostics. Partial walking still produces useful findings on
/// minified or slightly-broken bundles.
pub struct ParsedProgram<'alloc> {
    #[allow(dead_code)]
    allocator: &'alloc oxc_allocator::Allocator,
    pub program: Program<'alloc>,
}

impl<'alloc> ParsedProgram<'alloc> {
    pub fn parse(
        allocator: &'alloc oxc_allocator::Allocator,
        source: &'alloc str,
        source_type: oxc_span::SourceType,
    ) -> Self {
        let ret = oxc_parser::Parser::new(allocator, source, source_type).parse();
        Self {
            allocator,
            program: ret.program,
        }
    }
}

// ---------- shared visitors ----------------------------------------------

/// A visitor that flags an `ObjectProperty` whose key is `target_key` and
/// whose value is a `BooleanLiteral` of `target_value`. Used by every
/// `webPreferences` rule because they all look the same:
/// `{ sandbox: false }`, `{ nodeIntegration: true }`, …
///
/// The visitor doesn't verify the enclosing object is specifically a
/// `webPreferences` literal — doing so correctly requires taint analysis
/// (the object may be spread, aliased, built up in stages). The practical
/// cost of this laxity is rare false positives on object literals that
/// happen to use the same property name. In exchange we catch cases where
/// the `webPreferences` object is built across multiple assignments.
pub struct BoolPropertyVisitor<'a> {
    pub target_key: &'a str,
    pub target_value: bool,
    pub matches: Vec<AstMatch>,
    pub note: &'static str,
}

impl<'a, 'alloc> Visit<'alloc> for BoolPropertyVisitor<'a> {
    fn visit_object_expression(&mut self, obj: &ObjectExpression<'alloc>) {
        for prop in &obj.properties {
            if let ObjectPropertyKind::ObjectProperty(p) = prop {
                if prop_key_matches(&p.key, self.target_key) && bool_expr_is(&p.value, self.target_value)
                {
                    self.matches.push(AstMatch::new(p.span, self.note));
                }
            }
        }
        walk::walk_object_expression(self, obj);
    }
}

/// Flags every `shell.openExternal(...)` call (regardless of argument
/// shape). The caller decides confidence — we report *every* call with
/// `Tentative` confidence because the user must still eyeball whether the
/// URL argument is validated.
pub struct OpenExternalVisitor {
    pub matches: Vec<AstMatch>,
}

impl<'alloc> Visit<'alloc> for OpenExternalVisitor {
    fn visit_call_expression(&mut self, call: &CallExpression<'alloc>) {
        if is_call_like(&call.callee, "shell", "openExternal") {
            let note = if call.arguments.first().map_or(false, is_plain_string_arg) {
                "literal URL — likely safe"
            } else {
                "non-literal argument — needs manual review"
            };
            self.matches.push(AstMatch::new(call.span, note));
        }
        walk::walk_call_expression(self, call);
    }
}

// ---------- helpers -------------------------------------------------------

fn prop_key_matches(key: &PropertyKey<'_>, target: &str) -> bool {
    match key {
        PropertyKey::StaticIdentifier(id) => id.name.as_str() == target,
        PropertyKey::StringLiteral(s) => s.value.as_str() == target,
        _ => false,
    }
}

fn bool_expr_is(expr: &Expression<'_>, target: bool) -> bool {
    match expr {
        // `true` / `false` literal.
        Expression::BooleanLiteral(b) => b.value == target,
        // Minified `!0` / `!1`. `!0` = true, `!1` = false.
        Expression::UnaryExpression(u) if u.operator.as_str() == "!" => {
            if let Expression::NumericLiteral(n) = &u.argument {
                let min_is_false = (n.value - 1.0).abs() < f64::EPSILON; // `!1` → false
                let min_is_true = n.value == 0.0; // `!0` → true
                if target {
                    min_is_true
                } else {
                    min_is_false
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

/// True if `expr` is a member access of the form `<left_ident>.<right_ident>`.
fn is_call_like(expr: &Expression<'_>, left: &str, right: &str) -> bool {
    let Expression::StaticMemberExpression(m) = expr else {
        return false;
    };
    if m.property.name.as_str() != right {
        return false;
    }
    match &m.object {
        Expression::Identifier(id) => id.name.as_str() == left,
        _ => false,
    }
}

fn is_plain_string_arg(arg: &Argument<'_>) -> bool {
    matches!(arg, Argument::StringLiteral(_) | Argument::TemplateLiteral(_))
}

// Public getter so the scanner can ignore object-property matches that
// aren't syntactically inside an object literal — currently unused because
// `BoolPropertyVisitor` already drives from an object expression.
#[allow(dead_code)]
pub fn is_object_property(_p: &ObjectProperty<'_>) -> bool {
    true
}
