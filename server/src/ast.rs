use tree_sitter::{Node, Parser, Tree};

/// Parsed function information
#[derive(Debug, Clone)]
pub struct FnInfo {
    pub name: String,
    pub is_public: bool,
    pub start_line: usize, // 1-indexed
    pub node_id: usize,    // tree-sitter node id for lookups
    pub args: Vec<String>, // arguments like "to", "amount"
}

/// Parsed struct field information
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: String, // e.g. "Mapping<Address, U256>"
}

/// A method call found in the AST
#[derive(Debug, Clone)]
pub struct CallInfo {
    pub receiver: String, // e.g. "self.balances"
    pub line: usize,      // 1-indexed
}

/// Parse Rust source code into a tree-sitter Tree.
pub fn parse(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    let language = tree_sitter_rust::LANGUAGE;
    parser
        .set_language(&language.into())
        .expect("Error loading Rust grammar");
    parser.parse(source, None)
}

/// Extract all function definitions from the tree, marking public ones.
pub fn find_functions(tree: &Tree, source: &str) -> Vec<FnInfo> {
    let mut results = Vec::new();
    let root = tree.root_node();
    collect_functions(root, source, &mut results);
    results
}

fn collect_functions(node: Node, source: &str, results: &mut Vec<FnInfo>) {
    if node.kind() == "function_item" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        // Check for visibility modifier (pub, pub(crate), etc.)
        let is_public = has_visibility_modifier(node);

        // Parse arguments
        let mut args = Vec::new();
        if let Some(params) = node.child_by_field_name("parameters") {
            let mut cursor = params.walk();
            for param in params.children(&mut cursor) {
                if param.kind() == "parameter" {
                    if let Some(pat) = param.child_by_field_name("pattern") {
                        if let Ok(text) = pat.utf8_text(source.as_bytes()) {
                            args.push(text.to_string());
                        }
                    }
                }
            }
        }

        results.push(FnInfo {
            name,
            is_public,
            start_line: node.start_position().row + 1,
            node_id: node.id(),
            args,
        });
    }

    // Recurse into children (handles impl blocks, modules, etc.)
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_functions(child, source, results);
    }
}

fn has_visibility_modifier(node: Node) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            return true;
        }
        // Stop after first non-attribute/non-visibility child
        if child.kind() != "attribute_item" && child.kind() != "line_comment" {
            break;
        }
    }
    false
}

/// Extract struct fields, especially looking for Mapping<...> types.
pub fn find_struct_fields(tree: &Tree, source: &str) -> Vec<FieldInfo> {
    let mut results = Vec::new();
    let root = tree.root_node();
    collect_struct_fields(root, source, &mut results);
    results
}

fn collect_struct_fields(node: Node, source: &str, results: &mut Vec<FieldInfo>) {
    if node.kind() == "field_declaration" {
        let name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        let type_name = node
            .child_by_field_name("type")
            .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        if !name.is_empty() {
            results.push(FieldInfo {
                name,
                type_name,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_struct_fields(child, source, results);
    }
}

/// Check if a function body contains authorization/guard patterns.
/// This is scope-aware: it only checks within the function's actual body block.
pub fn body_contains_guard(tree: &Tree, func: &FnInfo, source: &str) -> bool {
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            let body_text = body
                .utf8_text(source.as_bytes())
                .unwrap_or("");
            return text_contains_guard(body_text);
        }
    }
    false
}

/// Check if given text contains common authorization/guard patterns.
fn text_contains_guard(text: &str) -> bool {
    const GUARD_PATTERNS: &[&str] = &[
        "env::caller()",
        "self.env().caller()",
        "get_caller",
        "assert!",
        "assert_eq!",
        "revert(",
        "unwrap_or_revert",
        "access_control",
        "assert_role",
        "is_admin",
        "only_owner",
    ];
    for pattern in GUARD_PATTERNS {
        if text.contains(pattern) {
            return true;
        }
    }
    false
}

/// Find all method calls within a function body.
/// Returns calls matching the given method name (e.g. "set", "unwrap").
pub fn find_method_calls_in_fn(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
    method_name: &str,
) -> Vec<CallInfo> {
    let mut results = Vec::new();
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_method_calls(body, source, method_name, &mut results);
        }
    }
    results
}

fn collect_method_calls(node: Node, source: &str, method_name: &str, results: &mut Vec<CallInfo>) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            if func_node.kind() == "field_expression" {
                let method = func_node
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("");

                if method == method_name {
                    let receiver = func_node
                        .child_by_field_name("value")
                        .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                        .unwrap_or("")
                        .to_string();

                    results.push(CallInfo {
                        receiver,
                        line: node.start_position().row + 1,
                    });
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_method_calls(child, source, method_name, results);
    }
}

/// Find all free function calls (not method calls) within a function body.
/// E.g. `runtime::call_contract(...)`, `transfer_from_purse_to_account(...)`.
pub fn find_function_calls_in_fn(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
    target_fn: &str,
) -> Vec<CallInfo> {
    let mut results = Vec::new();
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_function_calls(body, source, target_fn, &mut results);
        }
    }
    results
}

fn collect_function_calls(
    node: Node,
    source: &str,
    target_fn: &str,
    results: &mut Vec<CallInfo>,
) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let call_text = func_node
                .utf8_text(source.as_bytes())
                .unwrap_or("");
            if call_text.contains(target_fn) {
                results.push(CallInfo {
                    receiver: String::new(),
                    line: node.start_position().row + 1,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_function_calls(child, source, target_fn, results);
    }
}

/// Check if a function call's result is properly handled (match, unwrap_or_revert, etc.)
pub fn is_call_result_handled(tree: &Tree, func: &FnInfo, source: &str, call_line: usize) -> bool {
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            return check_result_handling(body, source, call_line);
        }
    }
    false
}

fn check_result_handling(node: Node, source: &str, target_line: usize) -> bool {
    // Check if the call is inside a match expression
    if node.kind() == "match_expression" {
        let node_text = node.utf8_text(source.as_bytes()).unwrap_or("");
        if node.start_position().row < target_line
            && node.end_position().row + 1 >= target_line
        {
            return true;
        }
        if node_text.contains("unwrap_or_revert") {
            return true;
        }
    }

    // Check the line itself for .unwrap_or_revert or match
    let lines: Vec<&str> = source.lines().collect();
    if target_line > 0 && target_line <= lines.len() {
        let line = lines[target_line - 1];
        if line.contains("unwrap_or_revert") || line.contains("match ") {
            return true;
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if check_result_handling(child, source, target_line) {
            return true;
        }
    }
    false
}

/// Check if there is a state update (`.set()` or `storage::write`) before a given line
/// within the same function body. Used for reentrancy detection (CEI pattern).
pub fn has_state_update_before_line(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
    call_line: usize,
) -> bool {
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");
            let body_start_line = body.start_position().row + 1;

            // Check each line in the body before the call_line
            for (i, line) in body_text.lines().enumerate() {
                let absolute_line = body_start_line + i;
                if absolute_line >= call_line {
                    break;
                }
                if line.contains(".set(") || line.contains("storage::write") {
                    return true;
                }
            }
        }
    }
    false
}

/// Find all string literal arguments in function calls (for hardcoded key detection).
pub fn find_string_literal_args_in_fn(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
    target_fn: &str,
) -> Vec<usize> {
    let mut lines = Vec::new();
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_string_arg_calls(body, source, target_fn, &mut lines);
        }
    }
    lines
}

fn collect_string_arg_calls(
    node: Node,
    source: &str,
    target_fn: &str,
    lines: &mut Vec<usize>,
) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let call_text = func_node.utf8_text(source.as_bytes()).unwrap_or("");
            if call_text.contains(target_fn) {
                // Check if any argument is a string literal
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for arg in args.children(&mut cursor) {
                        if arg.kind() == "string_literal" {
                            lines.push(node.start_position().row + 1);
                            break;
                        }
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_string_arg_calls(child, source, target_fn, lines);
    }
}

/// Check if a node contains `.unwrap()` calls (not inside comments).
pub fn find_unwrap_calls_in_fn(tree: &Tree, func: &FnInfo, source: &str) -> Vec<usize> {
    let calls = find_method_calls_in_fn(tree, func, source, "unwrap");
    calls.iter().map(|c| c.line).collect()
}

/// Check for binary operations (+, *) involving U256 types in a function.
pub fn find_unsafe_arithmetic_in_fn(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
) -> Vec<usize> {
    let mut results = Vec::new();
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_unsafe_arithmetic(body, source, &mut results);
        }
    }
    results
}

fn collect_unsafe_arithmetic(node: Node, source: &str, results: &mut Vec<usize>) {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
            if op_text == "+" || op_text == "*" {
                let expr_text = node.utf8_text(source.as_bytes()).unwrap_or("");
                // Check if expression involves U256
                let line = node.start_position().row + 1;
                let lines: Vec<&str> = source.lines().collect();
                if line > 0 && line <= lines.len() {
                    let source_line = lines[line - 1];
                    if source_line.contains("U256") || expr_text.contains("U256") {
                        results.push(line);
                        return; // don't recurse into children of this expression
                    }
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_unsafe_arithmetic(child, source, results);
    }
}

/// Check for division (/) or modulo (%) operations in a function.
pub fn find_division_in_fn(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
) -> Vec<usize> {
    let mut results = Vec::new();
    let root = tree.root_node();
    if let Some(fn_node) = find_node_by_id(root, func.node_id) {
        if let Some(body) = fn_node.child_by_field_name("body") {
            collect_division(body, source, &mut results);
        }
    }
    results
}

fn collect_division(node: Node, source: &str, results: &mut Vec<usize>) {
    if node.kind() == "binary_expression" {
        if let Some(op) = node.child_by_field_name("operator") {
            let op_text = op.utf8_text(source.as_bytes()).unwrap_or("");
            if op_text == "/" || op_text == "%" {
                let line = node.start_position().row + 1;
                results.push(line);
                return; // don't recurse into children of this expression
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_division(child, source, results);
    }
}

// --- Internal helpers ---

pub fn find_node_by_id(node: Node, target_id: usize) -> Option<Node> {
    if node.id() == target_id {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_node_by_id(child, target_id) {
            return Some(found);
        }
    }
    None
}
