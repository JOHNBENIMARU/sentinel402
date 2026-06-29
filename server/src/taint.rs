use crate::ast::{self, FnInfo};
use tree_sitter::Tree;

/// Returns a list of (argument_name, line_number) representing tainted inputs
/// that are passed to critical sinks without sanitization.
pub fn find_tainted_usages(
    tree: &Tree,
    func: &FnInfo,
    source: &str,
    sinks: &[&str],
) -> Vec<(String, usize)> {
    let mut tainted_usages = Vec::new();

    let root = tree.root_node();
    let fn_node = match ast::find_node_by_id(root, func.node_id) {
        Some(node) => node,
        None => return tainted_usages,
    };

    let body_node = match fn_node.child_by_field_name("body") {
        Some(node) => node,
        None => return tainted_usages,
    };

    let body_text = body_node.utf8_text(source.as_bytes()).unwrap_or("");

    for arg in &func.args {
        // Skip self arguments
        if arg == "self" || arg == "&self" || arg == "&mut self" || arg == "_" || arg.starts_with('_') {
            continue;
        }

        // 1. Check if the argument is "sanitized".
        // A simple heuristic for MVP: if the argument is used inside an assert! or an if statement,
        // we consider it sanitized.
        let is_sanitized = body_text.contains(&format!("assert!("))
            || body_text.contains(&format!("assert_eq!("))
            || body_text.contains(&format!("unwrap_or_revert"))
            || body_text.contains(&format!("if {} ", arg))
            || body_text.contains(&format!("if {}=", arg))
            || body_text.contains(&format!("if {}!", arg))
            || body_text.contains(&format!("if {}<", arg))
            || body_text.contains(&format!("if {}>", arg))
            || body_text.contains("access_control")
            || body_text.contains("assert_role")
            || body_text.contains("get_caller");

        if is_sanitized {
            continue;
        }

        // 2. Check if the argument is used in a sink.
        // We'll walk the body looking for call expressions matching the sinks.
        let mut cursor = body_node.walk();
        let mut sink_lines = Vec::new();
        find_sinks_using_arg(body_node, source, arg, sinks, &mut cursor, &mut sink_lines);

        for line in sink_lines {
            tainted_usages.push((arg.clone(), line));
        }
    }

    tainted_usages
}

fn find_sinks_using_arg(
    node: tree_sitter::Node,
    source: &str,
    arg: &str,
    sinks: &[&str],
    cursor: &mut tree_sitter::TreeCursor,
    results: &mut Vec<usize>,
) {
    if node.kind() == "call_expression" || node.kind() == "method_invocation" {
        let text = node.utf8_text(source.as_bytes()).unwrap_or("");
        
        // Check if this call is one of our sinks
        let is_sink = sinks.iter().any(|&sink| text.contains(sink));
        
        if is_sink {
            // Check if the argument is passed in this call
            // We just do a simple string match inside the arguments node
            if let Some(args_node) = node.child_by_field_name("arguments") {
                let args_text = args_node.utf8_text(source.as_bytes()).unwrap_or("");
                // To avoid partial matches (e.g. arg "to" matching "token"), we could regex, 
                // but a simple text check is okay for MVP if we pad with non-alphanumeric.
                // Or simply:
                if args_text.contains(arg) {
                    results.push(node.start_position().row + 1);
                }
            }
        }
    }

    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        find_sinks_using_arg(child, source, arg, sinks, cursor, results);
    }
}
