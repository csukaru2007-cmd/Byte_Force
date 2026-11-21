"""Turn Clang translation units into a structured, per-file feature representation.

Only AST nodes whose source location lies inside the uploaded project are recorded
(stub headers and system headers are skipped). Every record keeps file, line and the
enclosing function, and call records keep the *declaration* Clang resolved the call to
(class, base classes, qualified name), not just the spelling.

Known limits (also reported in the scan): calls through function pointers, callbacks
and virtual dispatch are recorded as `indirect_calls` with no resolved target; data
flow is not tracked across functions or files; code removed by #if is not seen.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

import clang.cindex as cindex

from backend.ast_engine.clang_parser import ParseResult, evaluate

CK = cindex.CursorKind
TK = cindex.TypeKind

FUNCTION_KINDS = {CK.FUNCTION_DECL, CK.CXX_METHOD, CK.CONSTRUCTOR, CK.DESTRUCTOR,
                  CK.FUNCTION_TEMPLATE, CK.CONVERSION_FUNCTION}
WRAPPERS = {CK.UNEXPOSED_EXPR, CK.PAREN_EXPR, CK.CSTYLE_CAST_EXPR, CK.CXX_STATIC_CAST_EXPR,
            CK.CXX_FUNCTIONAL_CAST_EXPR, CK.CXX_CONST_CAST_EXPR, CK.CXX_REINTERPRET_CAST_EXPR}
FOLDABLE = {CK.INTEGER_LITERAL, CK.FLOATING_LITERAL, CK.CHARACTER_LITERAL, CK.STRING_LITERAL,
            CK.DECL_REF_EXPR, CK.BINARY_OPERATOR, CK.UNARY_OPERATOR, CK.CONDITIONAL_OPERATOR,
            CK.CXX_BOOL_LITERAL_EXPR}
CAST_KINDS = {CK.CSTYLE_CAST_EXPR, CK.CXX_REINTERPRET_CAST_EXPR, CK.CXX_STATIC_CAST_EXPR}
ASSIGN_OPERATORS = {"=", "+=", "-=", "|=", "&=", "^=", "<<=", ">>="}

# ---------------------------------------------------------------- GPIO-related APIs
# value: list of (role, argument index, requirement); requirement "from_mode" uses MODE_ARG
GPIO_APIS: dict[tuple[str | None, str], list[tuple[str, int, str]]] = {
    (None, "pinMode"): [("pin", 0, "from_mode")],
    (None, "digitalWrite"): [("pin", 0, "output")],
    (None, "digitalRead"): [("pin", 0, "input")],
    (None, "analogRead"): [("pin", 0, "adc")],
    (None, "analogReadMilliVolts"): [("pin", 0, "adc")],
    (None, "analogWrite"): [("pin", 0, "output")],
    (None, "dacWrite"): [("pin", 0, "dac")],
    (None, "touchRead"): [("pin", 0, "touch")],
    (None, "ledcAttachPin"): [("pin", 0, "output")],
    (None, "ledcAttach"): [("pin", 0, "output")],
    (None, "ledcAttachChannel"): [("pin", 0, "output")],
    (None, "attachInterrupt"): [("pin", 0, "input")],
    (None, "gpio_set_direction"): [("pin", 0, "from_mode")],
    (None, "gpio_set_level"): [("pin", 0, "output")],
    (None, "gpio_get_level"): [("pin", 0, "input")],
    (None, "gpio_pullup_en"): [("pin", 0, "input_pull")],
    (None, "gpio_pulldown_en"): [("pin", 0, "input_pull")],
    (None, "gpio_set_pull_mode"): [("pin", 0, "input_pull")],
    (None, "gpio_reset_pin"): [("pin", 0, "any")],
    ("TwoWire", "setPins"): [("SDA", 0, "output"), ("SCL", 1, "output")],
    ("SPIClass", "begin"): [("SCK", 0, "output"), ("MISO", 1, "input"), ("MOSI", 2, "output"), ("SS", 3, "output")],
    ("HardwareSerial", "begin"): [("RX", 2, "input"), ("TX", 3, "output")],
    ("HardwareSerial", "setPins"): [("RX", 0, "input"), ("TX", 1, "output")],
}
MODE_ARG = {"pinMode": 1, "gpio_set_direction": 1}
# esp32-hal-gpio.h values / ESP-IDF gpio_mode_t
ARDUINO_MODES = {0x01: "INPUT", 0x03: "OUTPUT", 0x04: "PULLUP", 0x05: "INPUT_PULLUP", 0x08: "PULLDOWN",
                 0x09: "INPUT_PULLDOWN", 0x10: "OPEN_DRAIN", 0x13: "OUTPUT_OPEN_DRAIN", 0xC0: "ANALOG"}
IDF_MODES = {0: "GPIO_MODE_DISABLE", 1: "GPIO_MODE_INPUT", 2: "GPIO_MODE_OUTPUT", 6: "GPIO_MODE_OUTPUT_OD",
             7: "GPIO_MODE_INPUT_OUTPUT_OD", 3: "GPIO_MODE_INPUT_OUTPUT"}
MODE_REQUIREMENT = {
    "INPUT": "input", "GPIO_MODE_INPUT": "input",
    "OUTPUT": "output", "OPEN_DRAIN": "output", "OUTPUT_OPEN_DRAIN": "output",
    "GPIO_MODE_OUTPUT": "output", "GPIO_MODE_OUTPUT_OD": "output",
    "GPIO_MODE_INPUT_OUTPUT": "output", "GPIO_MODE_INPUT_OUTPUT_OD": "output",
    "INPUT_PULLUP": "input_pull", "INPUT_PULLDOWN": "input_pull", "PULLUP": "input_pull", "PULLDOWN": "input_pull",
    "ANALOG": "analog", "GPIO_MODE_DISABLE": "none",
}


@dataclass
class FileFeatures:
    file: str
    origin: str
    function_declarations: list[dict] = field(default_factory=list)
    function_calls: list[dict] = field(default_factory=list)
    object_declarations: list[dict] = field(default_factory=list)
    variable_declarations: list[dict] = field(default_factory=list)
    string_literals: list[dict] = field(default_factory=list)
    assignments: list[dict] = field(default_factory=list)
    array_initializers: list[dict] = field(default_factory=list)
    function_pointer_casts: list[dict] = field(default_factory=list)
    indirect_calls: list[dict] = field(default_factory=list)
    unresolved_calls: list[dict] = field(default_factory=list)
    macro_definitions: list[dict] = field(default_factory=list)
    gpio_operations: list[dict] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self) -> dict:
        counts = {name: len(value) for name, value in asdict(self).items() if isinstance(value, list)}
        return {"file": self.file, "origin": self.origin, "counts": counts}


@dataclass
class ProjectFeatures:
    files: dict[str, FileFeatures] = field(default_factory=dict)
    parse_results: list[ParseResult] = field(default_factory=list)

    def iter(self, feature: str) -> Iterator[tuple[FileFeatures, dict]]:
        for features in self.files.values():
            for item in getattr(features, feature):
                yield features, item

    def calls_matching(self, predicate) -> list[tuple[FileFeatures, dict]]:
        return [(f, c) for f, c in self.iter("function_calls") if predicate(c)]


def origin_of(rel: str) -> str:
    parts = rel.split("/")
    if parts[0] == "lib" and len(parts) > 2:
        return f"dependency:{parts[1]}"
    if parts[:2] == [".pio", "libdeps"] and len(parts) > 4:
        return f"dependency:{parts[3]}"
    return "project"


_STRING_TOKEN = re.compile(r'^(u8|u|U|L)?R?"', re.DOTALL)


def decode_c_string(token: str) -> str:
    """Decode one C/C++ string-literal token (prefixes, escapes, raw strings)."""
    body = re.sub(r"^(u8|u|U|L)", "", token)
    if body.startswith('R"'):
        match = re.match(r'^R"([^(]*)\((.*)\)\1"$', body, re.DOTALL)
        return match.group(2) if match else body[2:-1]
    if len(body) >= 2 and body[0] == '"' and body[-1] == '"':
        inner = body[1:-1]
        try:
            return ast.literal_eval('"' + inner.replace("\n", "\\n") + '"')
        except (ValueError, SyntaxError):
            return inner
    return token


def literal_string(cursor) -> str:
    """Value of a STRING_LITERAL cursor, including adjacent-literal concatenation."""
    value = evaluate(cursor)
    if isinstance(value, str):
        return value
    try:
        pieces = [t.spelling for t in cursor.get_tokens()]
    except Exception:  # noqa: BLE001
        pieces = []
    if not pieces or not all(_STRING_TOKEN.match(p) for p in pieces):
        pieces = [cursor.spelling]          # literal produced by a macro: spelling is the literal itself
    return "".join(decode_c_string(p) for p in pieces)


def clean_type_name(type_obj) -> str:
    t = type_obj
    for _ in range(4):
        if t.kind in (TK.POINTER, TK.LVALUEREFERENCE, TK.RVALUEREFERENCE):
            t = t.get_pointee()
    t = t.get_canonical() if t.kind == TK.TYPEDEF or t.kind == TK.ELABORATED else t
    name = t.spelling
    for prefix in ("const ", "volatile ", "class ", "struct ", "enum "):
        name = name.replace(prefix, "")
    return name.strip()


class ASTExtractor:
    def __init__(self, project_root: Path):
        self.root = project_root.resolve()
        self.features = ProjectFeatures()
        self._seen: set[tuple] = set()
        self._bases_cache: dict[str, list[str]] = {}

    # ------------------------------------------------------------ helpers
    def _rel(self, cursor) -> str | None:
        loc_file = cursor.location.file
        if loc_file is None:
            return None
        path = Path(loc_file.name)
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return None

    def _file(self, rel: str) -> FileFeatures:
        if rel not in self.features.files:
            self.features.files[rel] = FileFeatures(rel, origin_of(rel))
        return self.features.files[rel]

    def _once(self, *key) -> bool:
        if key in self._seen:
            return False
        self._seen.add(key)
        return True

    @staticmethod
    def _text(cursor, limit: int = 240, anchor_offset: int | None = None) -> str:
        """Source text of a node. Nodes produced by a macro have an extent that starts at the
        #define, so when the extent starts before `anchor_offset` the spelling is used instead."""
        extent = cursor.extent
        sane = (extent.start.file is not None and extent.end.file is not None
                and extent.start.file.name == extent.end.file.name
                and extent.start.offset <= extent.end.offset
                and (anchor_offset is None or extent.start.offset >= anchor_offset))
        text = ""
        if sane:
            try:
                text = " ".join(t.spelling for t in cursor.get_tokens())
            except Exception:  # noqa: BLE001
                text = ""
        if not text or "#" in text.split():
            text = cursor.spelling or ""
        return text if len(text) <= limit else text[:limit] + "..."

    def _call_arg_texts(self, cursor, callee: str) -> list[str] | None:
        """Split the call's own tokens at top-level commas: robust for macro arguments."""
        try:
            tokens = [t.spelling for t in cursor.get_tokens()]
        except Exception:  # noqa: BLE001
            return None
        if not tokens or tokens[-1] != ")" or "#" in tokens:
            return None
        depth, start = 0, None
        for index in range(len(tokens) - 1, -1, -1):
            if tokens[index] in (")", "]", "}"):
                depth += 1
            elif tokens[index] in ("(", "[", "{"):
                depth -= 1
                if depth == 0:
                    start = index
                    break
        if start is None or callee not in tokens[:start]:
            return None             # call written through a macro: token layout is not the call's
        parts: list[str] = []
        current: list[str] = []
        depth = 0
        for token in tokens[start + 1:-1]:
            if token in ("(", "[", "{"):
                depth += 1
            elif token in (")", "]", "}"):
                depth -= 1
            if token == "," and depth == 0:
                parts.append(" ".join(current))
                current = []
            else:
                current.append(token)
        if current or parts:
            parts.append(" ".join(current))
        return parts

    @staticmethod
    def _unwrap(cursor):
        seen = 0
        while cursor.kind in WRAPPERS and seen < 12:
            children = [c for c in cursor.get_children() if c.kind.is_expression()]
            if not children:
                break
            cursor = children[-1]
            seen += 1
        # implicit constructor conversions: String s = "x";  ->  look at "x"
        if cursor.kind == CK.CALL_EXPR and cursor.referenced is not None \
                and cursor.referenced.kind == CK.CONSTRUCTOR:
            args = list(cursor.get_arguments())
            if len(args) == 1:
                return ASTExtractor._unwrap(args[0])
        return cursor

    def _qualified(self, decl) -> str:
        parts = [decl.spelling]
        parent = decl.semantic_parent
        while parent is not None and parent.kind in (CK.NAMESPACE, CK.CLASS_DECL, CK.STRUCT_DECL,
                                                     CK.CLASS_TEMPLATE, CK.UNION_DECL):
            if parent.spelling:
                parts.append(parent.spelling)
            parent = parent.semantic_parent
        return "::".join(reversed(parts))

    def _bases(self, decl) -> list[str]:
        if decl is None or decl.kind not in (CK.CLASS_DECL, CK.STRUCT_DECL, CK.CLASS_TEMPLATE):
            return []
        key = decl.get_usr() or decl.spelling
        if key in self._bases_cache:
            return self._bases_cache[key]
        self._bases_cache[key] = []
        bases: list[str] = []
        for child in decl.get_children():
            if child.kind == CK.CXX_BASE_SPECIFIER:
                base_decl = child.type.get_declaration()
                name = base_decl.spelling or clean_type_name(child.type)
                bases.append(name)
                bases.extend(self._bases(base_decl))
        self._bases_cache[key] = bases
        return bases

    def _refs_and_calls(self, cursor) -> tuple[list[dict], list[str]]:
        refs: list[dict] = []
        calls: list[str] = []
        stack = [cursor]
        while stack:
            node = stack.pop()
            if node.kind in (CK.DECL_REF_EXPR, CK.MEMBER_REF_EXPR) and node.referenced is not None \
                    and node.referenced.kind in (CK.VAR_DECL, CK.PARM_DECL, CK.FIELD_DECL):
                refs.append({"name": node.referenced.spelling, "usr": node.referenced.get_usr()})
            elif node.kind == CK.CALL_EXPR and node.referenced is not None \
                    and not node.spelling.startswith("operator"):
                calls.append(self._qualified(node.referenced))
            stack.extend(node.get_children())
        return refs, calls

    def describe(self, expr, text: str | None = None, anchor_offset: int | None = None) -> dict:
        inner = self._unwrap(expr)
        value = None
        if inner.kind == CK.STRING_LITERAL:
            value = literal_string(inner)
        elif inner.kind in FOLDABLE or expr.kind in FOLDABLE:
            value = evaluate(expr)
            if value is None and inner is not expr:
                value = evaluate(inner)
        if inner.kind == CK.STRING_LITERAL:
            kind = "string_literal"
        elif inner.kind in (CK.INTEGER_LITERAL, CK.CHARACTER_LITERAL, CK.CXX_BOOL_LITERAL_EXPR):
            kind = "integer"
        elif inner.kind == CK.FLOATING_LITERAL:
            kind = "float"
        elif inner.kind in (CK.DECL_REF_EXPR, CK.MEMBER_REF_EXPR):
            kind = "reference"
        elif inner.kind == CK.CALL_EXPR:
            kind = "call"
        elif inner.kind == CK.LAMBDA_EXPR:
            kind = "lambda"
        else:
            kind = "expression"
        refs, calls = self._refs_and_calls(expr)
        if text is None:
            text = self._text(expr, anchor_offset=anchor_offset)
        macro = text if (kind in ("integer", "string_literal", "float") and text.isidentifier()) else None
        return {"text": text, "kind": kind, "value": value, "constant": value is not None,
                "type": expr.type.spelling, "references": refs, "calls": calls, "macro": macro}

    # ------------------------------------------------------------ main walk
    def extract(self, result: ParseResult) -> None:
        self.features.parse_results.append(result)
        tu = result.tu
        if tu is None:
            return
        stack: list[tuple[Any, str | None]] = [(child, None) for child in tu.cursor.get_children()]
        stack.reverse()
        while stack:
            cursor, func = stack.pop()
            rel = self._rel(cursor)
            if rel is None:
                continue            # stub / system header / generated empty header
            kind = cursor.kind
            next_func = func
            if kind in FUNCTION_KINDS:
                qualified = self._qualified(cursor)
                if cursor.is_definition():
                    next_func = qualified
                if self._once("fdecl", rel, cursor.location.line, qualified):
                    self._file(rel).function_declarations.append({
                        "name": cursor.spelling, "qualified_name": qualified, "line": cursor.location.line,
                        "is_definition": cursor.is_definition()})
            elif kind == CK.CALL_EXPR:
                self._call(cursor, rel, func)
            elif kind == CK.VAR_DECL:
                self._variable(cursor, rel, func)
            elif kind == CK.FIELD_DECL:
                self._object_decl(cursor, rel, func, scope="member")
            elif kind == CK.STRING_LITERAL:
                self._string(cursor, rel, func)
            elif kind in (CK.BINARY_OPERATOR, CK.COMPOUND_ASSIGNMENT_OPERATOR):
                self._assignment(cursor, rel, func)
            elif kind in CAST_KINDS:
                self._cast(cursor, rel, func)
            elif kind == CK.MACRO_DEFINITION:
                self._macro(cursor, rel)
                continue
            elif kind == CK.INCLUSION_DIRECTIVE:
                features = self._file(rel)
                if cursor.spelling not in features.includes:
                    features.includes.append(cursor.spelling)
                continue
            elif kind == CK.MACRO_INSTANTIATION:
                continue
            children = list(cursor.get_children())
            stack.extend((child, next_func) for child in reversed(children))

    # ------------------------------------------------------------ records
    def _call(self, cursor, rel: str, func: str | None) -> None:
        line, column = cursor.location.line, cursor.location.column
        spelling = cursor.spelling
        if spelling.startswith("operator"):
            if spelling == "operator=":
                self._overloaded_assignment(cursor, rel, func)
            return
        if not self._once("call", rel, line, column, spelling):
            return
        features = self._file(rel)
        ref = cursor.referenced
        arg_cursors = list(cursor.get_arguments())
        texts = self._call_arg_texts(cursor, spelling) if spelling else None
        anchor = cursor.extent.start.offset
        args = []
        for index, arg in enumerate(arg_cursors):
            if texts is not None:
                text = texts[index] if index < len(texts) else ""      # beyond written args: default argument
                args.append(self.describe(arg, text=text))
            else:
                args.append(self.describe(arg, anchor_offset=anchor))
        record: dict[str, Any] = {
            "name": spelling, "qualified_name": None, "class_name": None, "callee_kind": None,
            "object_name": None, "object_type": None, "object_bases": [], "display": spelling,
            "arguments": args, "line": line, "column": column, "enclosing_function": func or "<global>",
            "resolved": ref is not None,
        }
        children = list(cursor.get_children())
        member = next((self._unwrap_to_member(c) for c in children[:1]), None)
        if member is not None:
            objects = [c for c in member.get_children() if c.kind.is_expression()]
            if objects:
                # unwrap implicit derived-to-base casts so the *declared* object type is kept
                obj = self._unwrap(objects[0])
                obj_type = obj.type if obj.type.kind != TK.INVALID else objects[0].type
                record["object_name"] = obj.spelling or None
                record["object_type"] = clean_type_name(obj_type)
                canonical = obj_type.get_canonical()
                if canonical.kind in (TK.POINTER, TK.LVALUEREFERENCE, TK.RVALUEREFERENCE):
                    canonical = canonical.get_pointee()
                record["object_bases"] = self._bases(canonical.get_declaration())
        if ref is None:
            record["callee_kind"] = "unresolved"
            if not spelling:
                record["name"] = record["display"] = self._text(children[0], 60) if children else "<unknown>"
            features.unresolved_calls.append({"name": record["name"], "line": line,
                                              "enclosing_function": record["enclosing_function"]})
        elif ref.kind in (CK.VAR_DECL, CK.PARM_DECL, CK.FIELD_DECL):
            record["callee_kind"] = "indirect"
            features.indirect_calls.append({"through": ref.spelling, "type": ref.type.spelling, "line": line,
                                            "enclosing_function": record["enclosing_function"]})
        else:
            record["callee_kind"] = "constructor" if ref.kind == CK.CONSTRUCTOR else (
                "method" if ref.kind in (CK.CXX_METHOD, CK.CONVERSION_FUNCTION) else "function")
            record["qualified_name"] = self._qualified(ref)
            parent = ref.semantic_parent
            if parent is not None and parent.kind in (CK.CLASS_DECL, CK.STRUCT_DECL, CK.CLASS_TEMPLATE):
                record["class_name"] = parent.spelling
            if record["callee_kind"] == "constructor":
                record["object_type"] = record["class_name"]
        owner = record["object_name"] or record["object_type"]
        if owner and record["callee_kind"] != "constructor":
            record["display"] = f"{owner}.{record['name']}"
        features.function_calls.append(record)
        self._gpio(record, rel, features)

    def _unwrap_to_member(self, cursor):
        node = cursor
        for _ in range(4):
            if node.kind == CK.MEMBER_REF_EXPR:
                return node
            children = list(node.get_children())
            if node.kind != CK.UNEXPOSED_EXPR or not children:
                return None
            node = children[0]
        return None

    def _object_decl(self, cursor, rel: str, func: str | None, scope: str) -> None:
        decl_type = cursor.type.get_canonical()
        if decl_type.kind == TK.POINTER:
            decl_type = decl_type.get_pointee()
        if decl_type.kind != TK.RECORD:
            return
        if self._once("obj", rel, cursor.location.line, cursor.spelling):
            type_decl = decl_type.get_declaration()
            self._file(rel).object_declarations.append({
                "name": cursor.spelling, "type": clean_type_name(cursor.type),
                "bases": self._bases(type_decl), "line": cursor.location.line, "scope": scope,
                "enclosing_function": func or "<global>"})

    def _variable(self, cursor, rel: str, func: str | None) -> None:
        line = cursor.location.line
        if not self._once("var", rel, line, cursor.spelling):
            return
        scope = "local" if func else "global"
        self._object_decl(cursor, rel, func, scope)
        init_expr = None
        for child in cursor.get_children():
            if child.kind.is_expression():
                init_expr = child
        init = None
        if init_expr is not None:
            unwrapped = self._unwrap(init_expr)
            if unwrapped.kind == CK.INIT_LIST_EXPR:
                self._array(cursor, unwrapped, rel, func)
                init = {"text": "{...}", "kind": "initializer_list", "value": None, "constant": False,
                        "type": init_expr.type.spelling, "references": [], "calls": [], "macro": None}
            else:
                init = self.describe(init_expr, anchor_offset=cursor.extent.start.offset)
        type_obj = cursor.type
        self._file(rel).variable_declarations.append({
            "name": cursor.spelling, "usr": cursor.get_usr(), "type": type_obj.spelling,
            "is_const": type_obj.is_const_qualified() or "const" in type_obj.spelling.split(),
            "line": line, "scope": scope, "enclosing_function": func or "<global>", "init": init})

    def _array(self, var_cursor, init_list, rel: str, func: str | None) -> None:
        elements = [c for c in init_list.get_children()]
        integers = 0
        hex_literals = 0
        for element in elements:
            inner = self._unwrap(element)
            if inner.kind in (CK.INTEGER_LITERAL, CK.CHARACTER_LITERAL):
                integers += 1
                tokens = list(inner.get_tokens())
                if tokens and tokens[0].spelling.lower().startswith("0x"):
                    hex_literals += 1
        self._file(rel).array_initializers.append({
            "name": var_cursor.spelling, "usr": var_cursor.get_usr(), "type": var_cursor.type.spelling,
            "element_count": len(elements), "integer_count": integers, "hex_literal_count": hex_literals,
            "line": var_cursor.location.line, "enclosing_function": func or "<global>"})

    def _string(self, cursor, rel: str, func: str | None) -> None:
        line, column = cursor.location.line, cursor.location.column
        if not self._once("str", rel, line, column):
            return
        value = literal_string(cursor)
        self._file(rel).string_literals.append({
            "value": value, "length": len(value), "line": line, "column": column,
            "enclosing_function": func or "<global>"})

    def _assignment(self, cursor, rel: str, func: str | None) -> None:
        children = list(cursor.get_children())
        if len(children) != 2:
            return
        operator = self._operator(cursor, children[0])
        if operator not in ASSIGN_OPERATORS:
            return
        self._record_assignment(children[0], children[1], operator, rel, func, cursor.location.line,
                                anchor=cursor.extent.start.offset)

    def _overloaded_assignment(self, cursor, rel: str, func: str | None) -> None:
        args = list(cursor.get_arguments())
        children = [c for c in cursor.get_children() if c.kind.is_expression()]
        if len(args) == 1 and children:
            self._record_assignment(children[0], args[0], "=", rel, func, cursor.location.line,
                                    anchor=cursor.extent.start.offset)

    def _record_assignment(self, target, value, operator, rel, func, line, anchor=None) -> None:
        target_inner = self._unwrap(target)
        ref = target_inner.referenced
        name = target_inner.spelling or self._text(target, 60)
        if not self._once("assign", rel, line, name):
            return
        self._file(rel).assignments.append({
            "target": name, "target_usr": ref.get_usr() if ref is not None else None,
            "target_type": target.type.spelling, "operator": operator, "value": self.describe(value, anchor_offset=anchor),
            "line": line, "enclosing_function": func or "<global>"})

    @staticmethod
    def _operator(cursor, lhs) -> str | None:
        try:
            op = cursor.binary_operator          # libclang >= 17
            return {"Assign": "=", "AddAssign": "+=", "SubAssign": "-=", "OrAssign": "|=", "AndAssign": "&=",
                    "XorAssign": "^=", "ShlAssign": "<<=", "ShrAssign": ">>="}.get(op.name, op.name)
        except AttributeError:
            lhs_end = lhs.extent.end.offset
            for token in cursor.get_tokens():
                if token.extent.start.offset >= lhs_end:
                    return token.spelling
        return None

    def _cast(self, cursor, rel: str, func: str | None) -> None:
        target = cursor.type.get_canonical()
        if target.kind != TK.POINTER or target.get_pointee().kind not in (TK.FUNCTIONPROTO, TK.FUNCTIONNOPROTO):
            return
        operand = [c for c in cursor.get_children() if c.kind.is_expression()]
        if not operand:
            return
        source_type = operand[-1].type.get_canonical()
        if source_type.kind == TK.POINTER and source_type.get_pointee().kind in (TK.FUNCTIONPROTO, TK.FUNCTIONNOPROTO):
            return              # function pointer to function pointer: not data-to-code
        if not self._once("fpcast", rel, cursor.location.line, cursor.location.column):
            return
        refs, calls = self._refs_and_calls(operand[-1])
        self._file(rel).function_pointer_casts.append({
            "line": cursor.location.line, "to_type": cursor.type.spelling, "from_type": operand[-1].type.spelling,
            "operand": self._text(operand[-1], 120), "references": refs, "calls": calls,
            "enclosing_function": func or "<global>"})

    def _macro(self, cursor, rel: str) -> None:
        if cursor.spelling.startswith("_") or not self._once("macro", rel, cursor.location.line, cursor.spelling):
            return
        tokens = [t.spelling for t in cursor.get_tokens()][1:]
        body = " ".join(tokens)
        value = None
        if len(tokens) == 1 and tokens[0].startswith('"') and tokens[0].endswith('"'):
            value = tokens[0][1:-1]
        self._file(rel).macro_definitions.append({"name": cursor.spelling, "body": body[:240],
                                                  "string_value": value, "line": cursor.location.line})

    # ------------------------------------------------------------ GPIO operations
    def _gpio(self, call: dict, rel: str, features: FileFeatures) -> None:
        name = call["name"]
        class_name = call["class_name"]
        object_types = {class_name, call["object_type"], *call["object_bases"]} - {None}
        spec = None
        if class_name is None and call["callee_kind"] in ("function", "unresolved"):
            spec = GPIO_APIS.get((None, name))
        else:
            for candidate in object_types:
                spec = GPIO_APIS.get((candidate, name))
                if spec:
                    break
            if spec is None and name == "begin" and "TwoWire" in object_types:
                spec = [("SDA", 0, "output"), ("SCL", 1, "output")] if len(call["arguments"]) in (2, 3) else (
                    [("SDA", 1, "output"), ("SCL", 2, "output")] if len(call["arguments"]) == 4 else None)
        if not spec:
            return
        mode_name = None
        mode_requirement = None
        if name in MODE_ARG and len(call["arguments"]) > MODE_ARG[name]:
            mode = call["arguments"][MODE_ARG[name]]
            table = IDF_MODES if name.startswith("gpio_") else ARDUINO_MODES
            if mode["text"] in MODE_REQUIREMENT:
                mode_name = mode["text"]
            elif isinstance(mode["value"], int):
                mode_name = table.get(mode["value"])
            mode_requirement = MODE_REQUIREMENT.get(mode_name, "unknown") if mode_name else "unknown"
        for role, index, requirement in spec:
            if index >= len(call["arguments"]):
                continue
            arg = call["arguments"][index]
            value = arg["value"] if isinstance(arg["value"], int) else None
            if arg["text"] == "" or (value is not None and value < 0 and role != "pin"):
                continue        # defaulted argument or -1 = "pin not used"
            features.gpio_operations.append({
                "function": name, "api": call["qualified_name"] or name, "display": call["display"],
                "role": role, "gpio": value, "gpio_expr": arg["text"], "resolved": value is not None,
                "requirement": mode_requirement if requirement == "from_mode" else requirement,
                "mode": mode_name, "file": rel, "line": call["line"], "column": call["column"],
                "enclosing_function": call["enclosing_function"], "origin": features.origin,
                "callee_resolved": call["resolved"]})
