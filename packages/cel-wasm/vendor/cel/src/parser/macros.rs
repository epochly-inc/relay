use crate::common::ast::{
    operators, CallExpr, ComprehensionExpr, Expr, IdedExpr, ListExpr, LiteralValue, MapExpr,
};
use crate::parser::{MacroExprHelper, ParseError};

pub type MacroExpander = fn(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError>;

// Relay fork (G4): the synthetic function used to lower `transformMap`. It
// mirrors cel-go `ext` `cel.@mapInsert(accu, key, value) -> map`. Implemented
// as a special-cased call in `objects.rs`; it never appears in user source.
pub const MAP_INSERT: &str = "cel.@mapInsert";

pub fn find_expander(
    func_name: &str,
    target: Option<&IdedExpr>,
    args: &[IdedExpr],
) -> Option<MacroExpander> {
    match func_name {
        operators::HAS if args.len() == 1 && target.is_none() => Some(has_macro_expander),
        operators::EXISTS if args.len() == 2 && target.is_some() => Some(exists_macro_expander),
        operators::ALL if args.len() == 2 && target.is_some() => Some(all_macro_expander),
        operators::EXISTS_ONE | "existsOne" if args.len() == 2 && target.is_some() => {
            Some(exists_one_macro_expander)
        }
        operators::MAP if (args.len() == 2 || args.len() == 3) && target.is_some() => {
            Some(map_macro_expander)
        }
        operators::FILTER if args.len() == 2 && target.is_some() => Some(filter_macro_expander),

        // Relay fork (G4): two-variable comprehension macros
        // (cel-go `ext.TwoVarComprehensions`). The receiver forms take three
        // args (index/key var, value var, body) -- and four for the filtered
        // transforms (index/key var, value var, filter, transform). The
        // iteration variable distinguishes them from the one-variable forms.
        operators::ALL if args.len() == 3 && target.is_some() => Some(all2_macro_expander),
        operators::EXISTS if args.len() == 3 && target.is_some() => Some(exists2_macro_expander),
        operators::EXISTS_ONE | "existsOne" if args.len() == 3 && target.is_some() => {
            Some(exists_one2_macro_expander)
        }
        "transformList" if (args.len() == 3 || args.len() == 4) && target.is_some() => {
            Some(transform_list_macro_expander)
        }
        "transformMap" if (args.len() == 3 || args.len() == 4) && target.is_some() => {
            Some(transform_map_macro_expander)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Relay fork (G4): two-variable comprehension macros.
//
// These mirror cel-go `ext/comprehensions.go`. Each lowers to a comprehension
// whose `iter_var` holds the index (list) / key (map) and whose `iter_var2`
// holds the value. The comprehension engine (objects.rs) binds both vars when
// `iter_var2` is `Some`. The accumulator structure is identical to the
// one-variable forms; only the iteration binding differs.
//
// The two leading args are the iteration-variable identifiers; cel-go rejects
// duplicate names and names that shadow the accumulator. We mirror those
// guards so malformed expressions fail at parse time like the reference.
// ---------------------------------------------------------------------------

const ACCU_VAR: &str = "@result";

/// Pull the two iteration-variable identifiers out of the leading macro args,
/// enforcing cel-go's `extractIterVars` guards (no duplicates, no shadowing of
/// the accumulator). Relay fork (G4).
fn extract_iter_vars(
    var1: IdedExpr,
    var2: IdedExpr,
    helper: &mut MacroExprHelper,
) -> Result<(String, String), ParseError> {
    let v1_id = var1.id;
    let v2_id = var2.id;
    let iter_var1 = extract_ident(var1, helper)?;
    let iter_var2 = extract_ident(var2, helper)?;
    if iter_var1 == iter_var2 {
        return Err(ParseError {
            source: None,
            pos: helper.pos_for(v2_id).unwrap_or_default(),
            msg: format!("duplicate variable name: {iter_var1}"),
            expr_id: 0,
            source_info: None,
        });
    }
    if iter_var1 == ACCU_VAR {
        return Err(ParseError {
            source: None,
            pos: helper.pos_for(v1_id).unwrap_or_default(),
            msg: "iteration variable overwrites accumulator variable".to_string(),
            expr_id: 0,
            source_info: None,
        });
    }
    if iter_var2 == ACCU_VAR {
        return Err(ParseError {
            source: None,
            pos: helper.pos_for(v2_id).unwrap_or_default(),
            msg: "iteration variable overwrites accumulator variable".to_string(),
            expr_id: 0,
            source_info: None,
        });
    }
    Ok((iter_var1, iter_var2))
}

fn all2_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    let predicate = args.remove(2);
    let (iter_var1, iter_var2) = extract_iter_vars(args.remove(0), args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));
    let accu_ident = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let condition = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::NOT_STRICTLY_FALSE.to_string(),
        target: None,
        args: vec![accu_ident],
    }));

    let accu_step = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_AND.to_string(),
        target: None,
        args: vec![accu_step, predicate],
    }));

    let result = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: iter_var1,
            iter_var2: Some(iter_var2),
            accu_var: ACCU_VAR.to_string(),
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn exists2_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    let predicate = args.remove(2);
    let (iter_var1, iter_var2) = extract_iter_vars(args.remove(0), args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Boolean(false.into())));
    let accu_ident = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let negated = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_NOT.to_string(),
        target: None,
        args: vec![accu_ident],
    }));
    let condition = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::NOT_STRICTLY_FALSE.to_string(),
        target: None,
        args: vec![negated],
    }));

    let accu_step = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_OR.to_string(),
        target: None,
        args: vec![accu_step, predicate],
    }));

    let result = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: iter_var1,
            iter_var2: Some(iter_var2),
            accu_var: ACCU_VAR.to_string(),
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn exists_one2_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    let predicate = args.remove(2);
    let (iter_var1, iter_var2) = extract_iter_vars(args.remove(0), args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Int(0.into())));
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    // step = predicate ? @result + 1 : @result
    let accu_add = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let one = helper.next_expr(Expr::Literal(LiteralValue::Int(1.into())));
    let incremented = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::ADD.to_string(),
        target: None,
        args: vec![accu_add, one],
    }));
    let accu_keep = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::CONDITIONAL.to_string(),
        target: None,
        args: vec![predicate, incremented, accu_keep],
    }));

    // result = @result == 1
    let accu_result = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let one_result = helper.next_expr(Expr::Literal(LiteralValue::Int(1.into())));
    let result = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::EQUALS.to_string(),
        target: None,
        args: vec![accu_result, one_result],
    }));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: iter_var1,
            iter_var2: Some(iter_var2),
            accu_var: ACCU_VAR.to_string(),
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn transform_list_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    // args: [var1, var2, transform] or [var1, var2, filter, transform]
    let (filter, transform) = if args.len() == 4 {
        let transform = args.remove(3);
        let filter = args.remove(2);
        (Some(filter), transform)
    } else {
        (None, args.remove(2))
    };
    let (iter_var1, iter_var2) = extract_iter_vars(args.remove(0), args.remove(0), helper)?;

    let init = helper.next_expr(Expr::List(ListExpr::new(Vec::default())));
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    // step = @result + [transform]
    let accu = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let singleton = helper.next_expr(Expr::List(ListExpr::new(vec![transform])));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::ADD.to_string(),
        target: None,
        args: vec![accu, singleton],
    }));

    // with filter: step = filter ? (@result + [transform]) : @result
    let step = match filter {
        Some(filter) => {
            let accu_keep = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
            helper.next_expr(Expr::Call(CallExpr {
                func_name: operators::CONDITIONAL.to_string(),
                target: None,
                args: vec![filter, step, accu_keep],
            }))
        }
        None => step,
    };

    let result = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: iter_var1,
            iter_var2: Some(iter_var2),
            accu_var: ACCU_VAR.to_string(),
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn transform_map_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    // args: [var1, var2, transform] or [var1, var2, filter, transform]
    let (filter, transform) = if args.len() == 4 {
        let transform = args.remove(3);
        let filter = args.remove(2);
        (Some(filter), transform)
    } else {
        (None, args.remove(2))
    };
    let (iter_var1, iter_var2) = extract_iter_vars(args.remove(0), args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Map(MapExpr::default()));
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    // step = cel.@mapInsert(@result, iter_var1, transform)
    let accu = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
    let key_ident = helper.next_expr(Expr::Ident(iter_var1.clone()));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: MAP_INSERT.to_string(),
        target: None,
        args: vec![accu, key_ident, transform],
    }));

    // with filter: step = filter ? cel.@mapInsert(...) : @result
    let step = match filter {
        Some(filter) => {
            let accu_keep = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));
            helper.next_expr(Expr::Call(CallExpr {
                func_name: operators::CONDITIONAL.to_string(),
                target: None,
                args: vec![filter, step, accu_keep],
            }))
        }
        None => step,
    };

    let result = helper.next_expr(Expr::Ident(ACCU_VAR.to_string()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: iter_var1,
            iter_var2: Some(iter_var2),
            accu_var: ACCU_VAR.to_string(),
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn has_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_some() {
        unreachable!("Got a target when expecting `None`!")
    }
    if args.len() != 1 {
        unreachable!("Expected a single arg!")
    }

    let ided_expr = args.remove(0);
    match ided_expr.expr {
        Expr::Select(mut select) => {
            select.test = true;
            Ok(helper.next_expr(Expr::Select(select)))
        }
        _ => Err(ParseError {
            source: None,
            pos: helper.pos_for(ided_expr.id).unwrap_or_default(),
            msg: "invalid argument to has() macro".to_string(),
            expr_id: 0,
            source_info: None,
        }),
    }
}

fn exists_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_none() {
        unreachable!("Expected a target, but got `None`!")
    }
    if args.len() != 2 {
        unreachable!("Expected two args!")
    }

    let mut arguments = vec![args.remove(1)];
    let v = extract_ident(args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Boolean(false.into())));
    let result_binding = "@result".to_string();
    let accu_ident = helper.next_expr(Expr::Ident(result_binding.clone()));
    let arg = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_NOT.to_string(),
        target: None,
        args: vec![accu_ident],
    }));
    let condition = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::NOT_STRICTLY_FALSE.to_string(),
        target: None,
        args: vec![arg],
    }));

    arguments.insert(0, helper.next_expr(Expr::Ident(result_binding.clone())));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_OR.to_string(),
        target: None,
        args: arguments,
    }));

    let result = helper.next_expr(Expr::Ident(result_binding.clone()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: v,
            iter_var2: None,
            accu_var: result_binding,
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}
fn all_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_none() {
        unreachable!("Expected a target, but got `None`!")
    }
    if args.len() != 2 {
        unreachable!("Expected two args!")
    }

    let mut arguments = vec![args.remove(1)];
    let v = extract_ident(args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));
    let result_binding = "@result".to_string();
    let accu_ident = helper.next_expr(Expr::Ident(result_binding.clone()));
    let condition = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::NOT_STRICTLY_FALSE.to_string(),
        target: None,
        args: vec![accu_ident],
    }));

    arguments.insert(0, helper.next_expr(Expr::Ident(result_binding.clone())));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::LOGICAL_AND.to_string(),
        target: None,
        args: arguments,
    }));

    let result = helper.next_expr(Expr::Ident(result_binding.clone()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: v,
            iter_var2: None,
            accu_var: result_binding,
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn exists_one_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_none() {
        unreachable!("Expected a target, but got `None`!")
    }
    if args.len() != 2 {
        unreachable!("Expected two args!")
    }

    let mut arguments = vec![args.remove(1)];
    let v = extract_ident(args.remove(0), helper)?;

    let init = helper.next_expr(Expr::Literal(LiteralValue::Int(0.into())));
    let result_binding = "@result".to_string();
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    let args = vec![
        helper.next_expr(Expr::Ident(result_binding.clone())),
        helper.next_expr(Expr::Literal(LiteralValue::Int(1.into()))),
    ];
    arguments.push(helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::ADD.to_string(),
        target: None,
        args,
    })));
    arguments.push(helper.next_expr(Expr::Ident(result_binding.clone())));

    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::CONDITIONAL.to_string(),
        target: None,
        args: arguments,
    }));

    let accu = helper.next_expr(Expr::Ident(result_binding.clone()));
    let one = helper.next_expr(Expr::Literal(LiteralValue::Int(1.into())));
    let result = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::EQUALS.to_string(),
        target: None,
        args: vec![accu, one],
    }));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: v,
            iter_var2: None,
            accu_var: result_binding,
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn map_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_none() {
        unreachable!("Expected a target, but got `None`!")
    }
    if args.len() != 2 && args.len() != 3 {
        unreachable!("Expected two or three args!")
    }

    let func = args.pop().unwrap();
    let v = extract_ident(args.remove(0), helper)?;

    let init = helper.next_expr(Expr::List(ListExpr::new(Vec::default())));
    let result_binding = "@result".to_string();
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    let filter = args.pop();

    let args = vec![
        helper.next_expr(Expr::Ident(result_binding.clone())),
        helper.next_expr(Expr::List(ListExpr::new(vec![func]))),
    ];
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::ADD.to_string(),
        target: None,
        args,
    }));

    let step = match filter {
        Some(filter) => {
            let accu = helper.next_expr(Expr::Ident(result_binding.clone()));
            helper.next_expr(Expr::Call(CallExpr {
                func_name: operators::CONDITIONAL.to_string(),
                target: None,
                args: vec![filter, step, accu],
            }))
        }
        None => step,
    };

    let result = helper.next_expr(Expr::Ident(result_binding.clone()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: v,
            iter_var2: None,
            accu_var: result_binding,
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn filter_macro_expander(
    helper: &mut MacroExprHelper,
    target: Option<IdedExpr>,
    mut args: Vec<IdedExpr>,
) -> Result<IdedExpr, ParseError> {
    if target.is_none() {
        unreachable!("Expected a target, but got `None`!")
    }
    if args.len() != 2 {
        unreachable!("Expected two args!")
    }

    let var = args.remove(0);
    let v = extract_ident(var.clone(), helper)?;
    let filter = args.pop().unwrap();

    let init = helper.next_expr(Expr::List(ListExpr::new(Vec::default())));
    let result_binding = "@result".to_string();
    let condition = helper.next_expr(Expr::Literal(LiteralValue::Boolean(true.into())));

    let args = vec![
        helper.next_expr(Expr::Ident(result_binding.clone())),
        helper.next_expr(Expr::List(ListExpr::new(vec![var]))),
    ];
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::ADD.to_string(),
        target: None,
        args,
    }));

    let accu = helper.next_expr(Expr::Ident(result_binding.clone()));
    let step = helper.next_expr(Expr::Call(CallExpr {
        func_name: operators::CONDITIONAL.to_string(),
        target: None,
        args: vec![filter, step, accu],
    }));

    let result = helper.next_expr(Expr::Ident(result_binding.clone()));

    Ok(
        helper.next_expr(Expr::Comprehension(Box::new(ComprehensionExpr {
            iter_range: target.unwrap(),
            iter_var: v,
            iter_var2: None,
            accu_var: result_binding,
            accu_init: init,
            loop_cond: condition,
            loop_step: step,
            result,
        }))),
    )
}

fn extract_ident(expr: IdedExpr, helper: &mut MacroExprHelper) -> Result<String, ParseError> {
    match expr.expr {
        Expr::Ident(ident) => Ok(ident),
        _ => Err(ParseError {
            source: None,
            pos: helper.pos_for(expr.id).unwrap_or_default(),
            msg: "argument must be a simple name".to_string(),
            expr_id: 0,
            source_info: None,
        }),
    }
}
