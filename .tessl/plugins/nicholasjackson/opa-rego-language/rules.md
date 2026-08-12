# Rego Language Rules and Patterns

All rules in this document MUST be followed when generating or modifying Rego policy code.

---

## Mandatory Requirements

- **Write tests before implementing policies (TDD)**: Create the `_test.rego` file with test cases BEFORE writing the policy. Run `opa test` to confirm tests fail, then implement the policy until all tests pass. Every `.rego` file must have a corresponding `_test.rego` — a policy without tests is incomplete.

- **Never run Terraform commands**: Do NOT run `terraform plan`, `terraform apply`, `terraform init`, or any other Terraform CLI command. Create mock plan JSON inline in `_test.rego` using the `with` keyword, or ask the user to provide plan output.

- **Use `import rego.v1`**: Always include `import rego.v1` to opt in to v1 syntax (`if`, `contains`, `in`, `every` keywords). Never use `import future.keywords` — it is deprecated and cannot be combined with `import rego.v1`. Enforced by Regal [use-rego-v1](https://www.openpolicyagent.org/projects/regal/rules/imports/use-rego-v1).

- **Never import `input`**: Keep `input` references explicit (e.g., `input.resource.tags`). For Terraform IaC policies, never use `import input as tfplan` — normalise with `tfplan := object.get(input, "plan", input)` instead. Enforced by Regal [avoid-importing-input](https://www.openpolicyagent.org/projects/regal/rules/imports/avoid-importing-input).

---

## Metadata Annotations

Every package and every entrypoint rule MUST have a `# METADATA` annotation block. The block must be placed **immediately before** the target with no intervening lines — Regal [detached-metadata](https://www.openpolicyagent.org/projects/regal/rules/bugs/detached-metadata) flags any gap. Regal [missing-metadata](https://www.openpolicyagent.org/projects/regal/rules/custom/missing-metadata) flags packages or rules without annotations, and [no-defined-entrypoint](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/no-defined-entrypoint) flags policies with no entrypoint rule.

**Package-level annotation** (place before `package` declaration):
```rego
# METADATA
# title: My Policy
# description: What this policy enforces
# authors:
# - Team Name <team@example.com>
# custom:
#   category: kubernetes-admission
package my.policy

import rego.v1
```

**Rule-level annotation** (place immediately before the rule):
```rego
# METADATA
# title: Allow compliant requests
# description: Permits requests that pass all validation checks
# entrypoint: true
# custom:
#   severity: HIGH
allow if {
    count(deny) == 0
}
```

**Required fields for entrypoint rules**: `title`, `description`, `entrypoint: true`, `custom.severity` (HIGH, MEDIUM, or LOW). Enforced by Regal [invalid-metadata-attribute](https://www.openpolicyagent.org/projects/regal/rules/bugs/invalid-metadata-attribute) and [annotation-without-metadata](https://www.openpolicyagent.org/projects/regal/rules/bugs/annotation-without-metadata).

**Do NOT add `entrypoint: true` to Conftest policies** — Conftest queries rules by naming convention (`deny`, `warn`, `violation`) and does not use OPA's entrypoint mechanism.

**Runtime access**: Use `rego.metadata.rule()` to read a rule's own annotation at evaluation time (e.g., for severity-aware error formatting). No mocking needed — the metadata is baked into the policy source.

```rego
violation contains msg if {
    # ... violation logic ...
    meta := rego.metadata.rule()
    msg := {"message": "...", "severity": meta.custom.severity}
}
```

**Schema annotations**: Associate JSON schemas with `input` and `data` paths to enable `opa check` structural validation at build time.

---

## Module Structure

**Standard layout** — organise every module in this order:
1. `# METADATA` block (package-level)
2. `package` declaration
3. `import` statements
4. `default` declarations (always first, before the rules they apply to)
5. Constants and configuration
6. Helper rules and functions
7. Entrypoint rules

**Default declarations first**: Declare `default allow := false` and any other defaults at the top of the rules section, before the rule bodies that define when they are true. Regal [trailing-default-rule](https://www.openpolicyagent.org/projects/regal/rules/style/trailing-default-rule) flags defaults that appear after the rules they apply to.

**Imports before rules**: All `import` statements must appear before any rule declarations. Regal [import-after-rule](https://www.openpolicyagent.org/projects/regal/rules/imports/import-after-rule) flags imports that follow rules.

**Package mirrors directory**: `foo/bar/policy.rego` → `package foo.bar.policy`. Regal [directory-package-mismatch](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/directory-package-mismatch) flags mismatches.

**Separate concerns by package**: Keep related rules in the same package. Use separate packages for different policy domains.

---

## Naming Conventions

- **`snake_case` for all identifiers**: Rules, functions, variables, and constants — no camelCase or PascalCase. Regal [prefer-snake-case](https://www.openpolicyagent.org/projects/regal/rules/style/prefer-snake-case).
- **No `get_` or `list_` prefixes**: These are implied by Rego semantics. Use `user`, not `get_user`. Regal [avoid-get-and-list-prefix](https://www.openpolicyagent.org/projects/regal/rules/style/avoid-get-and-list-prefix).
- **No package path repetition in rule names**: If the package is `kubernetes.admission`, don't name a rule `kubernetes_admission_deny`. Regal [rule-name-repeats-package](https://www.openpolicyagent.org/projects/regal/rules/style/rule-name-repeats-package).
- **`is_` or `has_` prefix for boolean helpers**: `is_privileged`, `has_required_labels`.
- **`_` prefix for internal helpers**: Communicates that a rule is not part of the public API.
- **Descriptive test names**: Prefix with `test_`, describe what's being tested — `test_deny_privileged_container`.
- **No metasyntactic variable names**: Avoid `foo`, `bar`, `baz`, `tmp` — use meaningful names. Regal [metasyntactic-variable](https://www.openpolicyagent.org/projects/regal/rules/testing/metasyntactic-variable).

---

## Language Idioms

**Use `if` keyword**: Separates rule head from body. Required with `import rego.v1`. Regal [use-if](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-if).

**Use `contains` for partial set rules**: `deny contains msg if { ... }` not `deny[msg] { ... }`. Regal [use-contains](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-contains).

**Use `in` for membership checks**: `"admin" in input.user.roles` not `"admin" == input.user.roles[_]`. Regal [use-in-operator](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-in-operator).

**Use `some x in collection` for iteration**: Not `x := collection[_]`. Regal [prefer-some-in-iteration](https://www.openpolicyagent.org/projects/regal/rules/style/prefer-some-in-iteration). Don't mix iteration styles in the same rule — Regal [mixed-iteration](https://www.openpolicyagent.org/projects/regal/rules/style/mixed-iteration).

**Declare output variables with `some`**: When a variable is assigned inside a rule body for output (not just local use), declare it with `some`. Regal [use-some-for-output-vars](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-some-for-output-vars).

**Don't use `some` unnecessarily**: `some x in arr` is correct; `some x` alone before `x := value` is unnecessary when `x` is not an output variable. Regal [unnecessary-some](https://www.openpolicyagent.org/projects/regal/rules/style/unnecessary-some).

**`default` over `else`**: Use `default rule := value` for fallback values — the same pattern as `default allow := false`, applied to any rule. Declare the default first, then the specific rule heads. Do not use `else :=`. Regal [default-over-else](https://www.openpolicyagent.org/projects/regal/rules/style/default-over-else).

```rego
default user_limit := 10                                    # fallback first
user_limit := 1000 if data.user_tiers[input.user] == "premium"
user_limit := 100  if data.user_tiers[input.user] == "standard"
```

**`default` over negation**: Prefer `default allow := false` over `allow if not is_denied`. Regal [default-over-not](https://www.openpolicyagent.org/projects/regal/rules/style/default-over-not).

**Use `every` for universal quantification**: Express "for all" logic clearly instead of double-negation. `every container in spec.containers { not container.securityContext.privileged }`. Regal [double-negative](https://www.openpolicyagent.org/projects/regal/rules/style/double-negative).

**Boolean assignment via `if`**: Write `is_valid if { ... }` not `is_valid := true if { ... }`. Regal [boolean-assignment](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/boolean-assignment).

**Prefer set/object rules over comprehensions**: `violations contains v if { ... }` (multi-value rule) over `violations := { v | ... }` (top-level comprehension) — rules can be extended across files. Regal [prefer-set-or-object-rule](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/prefer-set-or-object-rule).

**Move assignment to comprehension term**: `{v.name | some v in input.items; v.active}` not `{name | some v in input.items; v.active; name := v.name}`. Regal [comprehension-term-assignment](https://www.openpolicyagent.org/projects/regal/rules/style/comprehension-term-assignment).

**Pattern matching in function arguments**: Use `f("foo") := ...` over `f(x) := ... if x == "foo"` when matching on a literal. Regal [equals-pattern-matching](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/equals-pattern-matching).

**Use `object.keys` over manual key extraction**: `object.keys(obj)` not `{k | obj[k]}`. Regal [use-object-keys](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-object-keys).

**Use `array.flatten` and `object.union_n`**: Prefer built-ins over nested `array.concat` or repeated `object.union` calls. Regal [use-array-flatten](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-array-flatten), [use-object-union-n](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-object-union-n).

**Use raw strings for regex**: `` regex.match(`[\d]+`, s) `` not `regex.match("[\\d]+", s)`. Regal [non-raw-regex-pattern](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/non-raw-regex-pattern).

**Prefer `==`/`!=` over `count` for empty checks**: `count(violations) == 0` → `violations == set()`. Regal [equals-over-count](https://www.openpolicyagent.org/projects/regal/rules/performance/equals-over-count).

**No wildcard key with `in`**: `some v in collection` not `some _, v in collection` when the key is unused. Regal [in-wildcard-key](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/in-wildcard-key).

**Avoid single-item `in`**: `input.user == "alice"` not `input.user in {"alice"}`. Regal [single-item-in](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/single-item-in).

**Use `strings.count` where possible**: Prefer `strings.count(s, sub)` over manual counting patterns. Regal [use-strings-count](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/use-strings-count).

---

## Functions

**No external references in functions**: Functions must operate only on their arguments — never reference `input` or `data` directly inside a function body. Pass data as explicit arguments. Regal [external-reference](https://www.openpolicyagent.org/projects/regal/rules/style/external-reference).

```rego
# Wrong — references input directly
is_admin := input.user.role == "admin"

# Correct — takes role as argument
is_admin(role) := role == "admin"
```

**Functions must have arguments**: Zero-argument functions that return a value should be rules instead. Regal [zero-arity-function](https://www.openpolicyagent.org/projects/regal/rules/bugs/zero-arity-function).

**Don't assign return value in argument**: Use `result := f(x)` not `f(x, result)` (last-argument return pattern). Regal [function-arg-return](https://www.openpolicyagent.org/projects/regal/rules/style/function-arg-return).

**Consistent argument names across function heads**: If a function has multiple heads, argument names must be consistent. Regal [inconsistent-args](https://www.openpolicyagent.org/projects/regal/rules/bugs/inconsistent-args).

**Arguments are not always wildcards**: If every call to a function passes `_` for an argument, the argument serves no purpose — remove it. Regal [argument-always-wildcard](https://www.openpolicyagent.org/projects/regal/rules/bugs/argument-always-wildcard).

---

## Import Rules

- **Import packages, not specific rules**: `import data.my.package` then `package.rule` — not `import data.my.package.rule`. Regal [prefer-package-imports](https://www.openpolicyagent.org/projects/regal/rules/imports/prefer-package-imports).
- **No circular imports**: Packages must not import each other cyclically. Regal [circular-import](https://www.openpolicyagent.org/projects/regal/rules/imports/circular-import).
- **No redundant aliases**: `import data.foo as foo` is pointless — omit the alias. Regal [redundant-alias](https://www.openpolicyagent.org/projects/regal/rules/imports/redundant-alias).
- **No confusing aliases**: Don't alias an import to a name that already exists. Regal [confusing-alias](https://www.openpolicyagent.org/projects/regal/rules/imports/confusing-alias).
- **No ignored imports**: Don't import something you don't use. Regal [ignored-import](https://www.openpolicyagent.org/projects/regal/rules/imports/ignored-import).
- **No import shadowing**: Imports must not shadow built-in namespaces or other imports. Regal [import-shadows-builtin](https://www.openpolicyagent.org/projects/regal/rules/imports/import-shadows-builtin), [import-shadows-import](https://www.openpolicyagent.org/projects/regal/rules/imports/import-shadows-import), [import-shadows-rule](https://www.openpolicyagent.org/projects/regal/rules/bugs/import-shadows-rule).
- **No redundant data import**: `import data` is implicit — never write it. Regal [redundant-data-import](https://www.openpolicyagent.org/projects/regal/rules/imports/redundant-data-import).
- **No pointless self-import**: A package must not import itself. Regal [pointless-import](https://www.openpolicyagent.org/projects/regal/rules/imports/pointless-import).
- **All imports must resolve**: Don't import packages that don't exist in the bundle. Regal [unresolved-import](https://www.openpolicyagent.org/projects/regal/rules/imports/unresolved-import), [unresolved-reference](https://www.openpolicyagent.org/projects/regal/rules/imports/unresolved-reference).

---

## Testing

- **`_test.rego` suffix**: Test files must be named `policy_test.rego` (not `policy.test.rego` or `test_policy.rego`). Regal [file-missing-test-suffix](https://www.openpolicyagent.org/projects/regal/rules/testing/file-missing-test-suffix).
- **`_test` package + import policy**: Test packages end in `_test` (e.g., `package my.policy_test`). Import the policy under test and reference rules via the alias — bare rule names are not in scope. Regal [test-outside-test-package](https://www.openpolicyagent.org/projects/regal/rules/testing/test-outside-test-package).
- **`test_` prefix on all test rules**: Every test function starts with `test_`. Regal enforces this via test discovery.
- **No duplicate test names**: Each test must have a unique name within the package. Regal [identically-named-tests](https://www.openpolicyagent.org/projects/regal/rules/testing/identically-named-tests).
- **No `todo_test_` in production**: `todo_test_` marks unimplemented tests (reported as SKIPPED). Remove or implement before shipping. Regal [todo-test](https://www.openpolicyagent.org/projects/regal/rules/testing/todo-test).
- **No `print` or `trace` in production code**: These are debugging tools only. Regal [print-or-trace-call](https://www.openpolicyagent.org/projects/regal/rules/testing/print-or-trace-call), [dubious-print-sprintf](https://www.openpolicyagent.org/projects/regal/rules/testing/dubious-print-sprintf).
- **No `with` outside tests**: `with` overrides are for test mocking only — not for production logic. Regal [with-outside-test-context](https://www.openpolicyagent.org/projects/regal/rules/performance/with-outside-test-context).
- **Cover both positive and negative cases**: Test that compliant input passes AND that non-compliant input is denied. Validate exact error messages.

---

## Bug Avoidance

- **No constant conditions**: `allow if 1 == 1` is meaningless. Every condition must check something meaningful. Regal [constant-condition](https://www.openpolicyagent.org/projects/regal/rules/bugs/constant-condition).
- **No duplicate rules**: Don't define the same rule body twice. Regal [duplicate-rule](https://www.openpolicyagent.org/projects/regal/rules/bugs/duplicate-rule).
- **Match `sprintf` argument count**: `sprintf("hello %v %v", [x])` with mismatched args will produce wrong output. Regal [sprintf-arguments-mismatch](https://www.openpolicyagent.org/projects/regal/rules/bugs/sprintf-arguments-mismatch).
- **No impossible `not`**: `not x` where `x` can never be true is always true — a logic error. Regal [impossible-not](https://www.openpolicyagent.org/projects/regal/rules/bugs/impossible-not).
- **No redundant existence checks**: Don't check `x != null` before accessing `x.field` if OPA will already fail safely on undefined. Regal [redundant-existence-check](https://www.openpolicyagent.org/projects/regal/rules/bugs/redundant-existence-check).
- **No `!=` in loops**: `some x in arr; x != "foo"` doesn't mean "no element equals foo" — it matches all elements except `"foo"`. Use `every` or `not` instead. Regal [not-equals-in-loop](https://www.openpolicyagent.org/projects/regal/rules/bugs/not-equals-in-loop).
- **No top-level iteration**: `x := input.items[_]` at package level fails when there are multiple items. Iteration belongs inside rule bodies. Regal [top-level-iteration](https://www.openpolicyagent.org/projects/regal/rules/bugs/top-level-iteration).
- **No rule/variable shadowing built-ins**: Don't name a rule or variable `print`, `count`, `array`, etc. Regal [rule-shadows-builtin](https://www.openpolicyagent.org/projects/regal/rules/bugs/rule-shadows-builtin), [var-shadows-builtin](https://www.openpolicyagent.org/projects/regal/rules/bugs/var-shadows-builtin).
- **Don't leak internal references**: Rules prefixed with `_` are internal — don't reference them from other packages. Regal [leaked-internal-reference](https://www.openpolicyagent.org/projects/regal/rules/bugs/leaked-internal-reference).
- **Assign non-boolean return values**: If a function returns a non-boolean, assign the result — `x := f(y)` not just `f(y)`. Regal [unassigned-return-value](https://www.openpolicyagent.org/projects/regal/rules/bugs/unassigned-return-value).
- **No unused output variables**: Every variable bound in a rule body must be used. Regal [unused-output-variable](https://www.openpolicyagent.org/projects/regal/rules/bugs/unused-output-variable).
- **No redundant count before loop**: `count(arr) > 0` before `some x in arr` is redundant — the loop body simply won't execute if empty. Regal [redundant-loop-count](https://www.openpolicyagent.org/projects/regal/rules/bugs/redundant-loop-count).
- **Don't assign the default value**: If `default x := false`, don't write a rule head `x := false if { ... }` — it's a no-op. Regal [rule-assigns-default](https://www.openpolicyagent.org/projects/regal/rules/bugs/rule-assigns-default).
- **No `if {}` with empty object**: `allow if {}` is a syntax error — empty objects after `if` are not rule bodies. Regal [if-empty-object](https://www.openpolicyagent.org/projects/regal/rules/bugs/if-empty-object), [if-object-literal](https://www.openpolicyagent.org/projects/regal/rules/bugs/if-object-literal).
- **No internal entrypoints**: Rules prefixed with `_` cannot be marked `entrypoint: true`. Regal [internal-entrypoint](https://www.openpolicyagent.org/projects/regal/rules/bugs/internal-entrypoint).
- **Don't name a rule `if`**: `if` is a keyword in OPA 1.0 — naming a rule `if` is a parse error. Regal [rule-named-if](https://www.openpolicyagent.org/projects/regal/rules/bugs/rule-named-if).
- **Call `time.now_ns()` once**: Cache the result in a variable — calling it twice in the same rule may return different values. Regal [time-now-ns-twice](https://www.openpolicyagent.org/projects/regal/rules/bugs/time-now-ns-twice).
- **No deprecated built-ins**: Functions removed in OPA 1.0: `any()`, `all()`, `re_match()`, `net.cidr_overlap()`, `set_diff()`, and all `cast_*()` functions. Use modern replacements (`regex.match`, `net.cidr_contains`, etc.). Regal [deprecated-builtin](https://www.openpolicyagent.org/projects/regal/rules/bugs/deprecated-builtin).

---

## Style and Formatting

- **Format with `opa fmt`**: All files must be formatted with `opa fmt`. Use `opa fmt --write` in CI. Regal [opa-fmt](https://www.openpolicyagent.org/projects/regal/rules/style/opa-fmt).
- **Use `:=` for assignment**: Never use `=` for assignment or comparison — `:=` assigns, `==` compares, `=` is unification (pattern matching only). Regal [use-assignment-operator](https://www.openpolicyagent.org/projects/regal/rules/style/use-assignment-operator).
- **`==` not `=` for equality**: Prefer `==` over `=` for equality comparisons. Regal [prefer-equals-comparison](https://www.openpolicyagent.org/projects/regal/rules/idiomatic/prefer-equals-comparison).
- **No Yoda conditions**: Write `x == "value"` not `"value" == x`. Regal [yoda-condition](https://www.openpolicyagent.org/projects/regal/rules/style/yoda-condition).
- **Comments start with a space**: `# comment` not `#comment`. Regal [no-whitespace-comment](https://www.openpolicyagent.org/projects/regal/rules/style/no-whitespace-comment).
- **No TODO comments**: Resolve outstanding work before committing. Regal [todo-comment](https://www.openpolicyagent.org/projects/regal/rules/style/todo-comment).
- **Line length ≤ 120 characters**: Break long expressions across multiple lines. Regal [line-length](https://www.openpolicyagent.org/projects/regal/rules/style/line-length).
- **Keep rules concise**: Long rule bodies are a sign of missing helper rules. Regal [rule-length](https://www.openpolicyagent.org/projects/regal/rules/style/rule-length), [file-length](https://www.openpolicyagent.org/projects/regal/rules/style/file-length).
- **No pointless reassignment**: Don't assign a variable to itself or to a value it already holds. Regal [pointless-reassignment](https://www.openpolicyagent.org/projects/regal/rules/style/pointless-reassignment).
- **No unconditional assignment in rule body**: `x := 1` with no condition belongs in the rule head, not the body. Regal [unconditional-assignment](https://www.openpolicyagent.org/projects/regal/rules/style/unconditional-assignment).
- **No messy incremental rules**: Partial set/object rules should be clean and focused — one concern per rule head. Regal [messy-rule](https://www.openpolicyagent.org/projects/regal/rules/style/messy-rule).

---

## Performance

- **Defer assignments**: Place assignments close to where they're used. Don't compute values before cheap guard conditions. Regal [defer-assignment](https://www.openpolicyagent.org/projects/regal/rules/performance/defer-assignment).
- **No non-loop expressions inside loops**: Move constant expressions out of loop bodies. Regal [non-loop-expression](https://www.openpolicyagent.org/projects/regal/rules/performance/non-loop-expression).
- **Optimise `walk` calls**: If you only need values (not paths) from `walk`, use `walk(x, [_, v])` and ignore the path. Regal [walk-no-path](https://www.openpolicyagent.org/projects/regal/rules/performance/walk-no-path).

---

## Design Patterns

- **Default deny**: Start with `default allow := false` and enumerate only safe conditions.
- **Deny/violation pattern**: Collect multiple failures as a set. `deny contains msg if { ... }` then gate `allow` on `count(deny) == 0`.
- **Extract helpers**: Repeated conditions become named helper rules — improves readability and enables memoization.
- **RBAC**: Map users → roles → permissions. Check if the requested action matches assigned permissions.
- **Set subtraction for unknown fields**: `{field | input.body[field]} - allowed_fields != set()` detects disallowed keys without iterating field by field.
- **`object.get` for safe access with defaults**: `object.get(obj, "key", default_value)` avoids undefined when a key may be absent.
- **Mock with `with` in tests**: `rule with input as mock with data.x as mock_data` — never use `with` in production rules.

---

## Architectural Conventions

- **Separate policy from data**: Store configuration and permissions in `data`. Reference from policy rules.
- **Package mirrors domain**: `kubernetes.admission`, `rbac.authz`, `terraform.analysis` — lowercase dot-separated hierarchy.
- **Layered packages**: Base (utilities) → domain (domain rules) → decision (composed output).
- **Policy-as-code**: Version policies in git. Use pull requests and CI (`opa test`, `opa check --strict`, `regal lint`) before deployment.
- **Run Regal in CI**: `regal lint` enforces all rules above automatically. Integrate as a required check.
