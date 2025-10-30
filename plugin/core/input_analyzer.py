# plugin/core/input_analyzer.py

from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import binaryninja as bn
from binaryninja import BinaryView, Function, Variable, Type
import struct

class ConstraintType(Enum):
    """Types of input constraints"""
    MAGIC_VALUE = "magic"
    LENGTH_CHECK = "length"
    RANGE_CHECK = "range"
    NULL_CHECK = "null"
    CHECKSUM = "checksum"
    ALIGNMENT = "alignment"
    FORMAT = "format"

@dataclass
class InputConstraint:
    """Represents a constraint on input data"""
    type: ConstraintType
    offset: Optional[int] = None
    size: Optional[int] = None
    value: Optional[Any] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    description: str = ""
    address: int = 0  # Where constraint is enforced

@dataclass
class StructField:
    """Represents a field in an input structure"""
    name: str
    offset: int
    size: int
    type_str: str
    access_count: int = 0
    is_pointer: bool = False
    is_array: bool = False
    array_size: Optional[int] = None

@dataclass
class InputSpec:
    """Complete specification of input format"""
    input_type: str  # "buffer", "struct", "string", "file", etc.
    size: Optional[int] = None
    min_size: Optional[int] = None
    max_size: Optional[int] = None
    structure: List[StructField] = field(default_factory=list)
    constraints: List[InputConstraint] = field(default_factory=list)
    format_hints: List[str] = field(default_factory=list)
    parameter_index: int = 0
    parameter_name: str = ""

class InputAnalyzer:
    """Analyzes how functions consume and validate input data"""

    def __init__(self, bv: BinaryView):
        self.bv = bv

    def analyze_function_input(self, func: Function, param_index: int = 0) -> InputSpec:
        """Complete input analysis for a specific parameter"""
        if param_index >= len(func.parameter_vars):
            return InputSpec(input_type="unknown")

        param = func.parameter_vars[param_index]
        param_type = func.type.parameters[param_index].type if func.type else None

        spec = InputSpec(
            parameter_index=param_index,
            parameter_name=param.name
        )

        # Determine input type from parameter type
        spec.input_type = self._infer_input_type(param_type)

        # Trace data flow from parameter
        data_flow = self._trace_data_flow(func, param)

        # Extract structure if it's a pointer to struct
        if param_type and param_type.type_class == bn.TypeClass.PointerTypeClass:
            pointee = param_type.target
            if pointee and pointee.type_class == bn.TypeClass.StructureTypeClass:
                spec.structure = self._extract_structure_definition(pointee)
            else:
                # Infer structure from access patterns
                spec.structure = self._infer_structure_from_accesses(func, param, data_flow)

        # Extract constraints
        spec.constraints = self._identify_constraints(func, param, data_flow)

        # Infer size bounds
        spec.min_size, spec.max_size = self._infer_size_bounds(func, param, spec.constraints)

        # Detect format hints
        spec.format_hints = self._extract_format_hints(func, param, data_flow)

        return spec

    def _infer_input_type(self, param_type: Optional[Type]) -> str:
        """Infer high-level input type from parameter type"""
        if not param_type:
            return "unknown"

        if param_type.type_class == bn.TypeClass.PointerTypeClass:
            target = param_type.target
            if target:
                if target.type_class == bn.TypeClass.IntegerTypeClass:
                    if target.width == 1:
                        return "buffer"  # uint8_t* or char*
                    return "buffer"
                elif target.type_class == bn.TypeClass.StructureTypeClass:
                    return "struct"
                elif target.type_class == bn.TypeClass.VoidTypeClass:
                    return "buffer"  # void*
            return "pointer"
        elif param_type.type_class == bn.TypeClass.IntegerTypeClass:
            return "integer"
        elif param_type.type_class == bn.TypeClass.StructureTypeClass:
            return "struct_value"

        return "unknown"

    def _trace_data_flow(self, func: Function, var: Variable) -> Dict[int, List]:
        """Trace data flow from variable through function"""
        data_flow = {}  # address -> list of operations

        if not func.hlil:
            return data_flow

        # Track all uses of the variable
        for block in func.hlil:
            for instr in block:
                if self._instruction_uses_var(instr, var):
                    if instr.address not in data_flow:
                        data_flow[instr.address] = []
                    data_flow[instr.address].append(instr)

        return data_flow

    def _instruction_uses_var(self, instr, var: Variable) -> bool:
        """Check if instruction uses the given variable"""
        if hasattr(instr, 'vars_read'):
            if var in instr.vars_read:
                return True

        # Recursively check operands
        for operand in instr.operands:
            if isinstance(operand, bn.highlevelil.HighLevelILInstruction):
                if self._instruction_uses_var(operand, var):
                    return True
            elif hasattr(operand, 'var') and operand.var == var:
                return True

        return False

    def _extract_structure_definition(self, struct_type: Type) -> List[StructField]:
        """Extract structure definition from type"""
        fields = []

        if struct_type.type_class != bn.TypeClass.StructureTypeClass:
            return fields

        structure = struct_type.structure
        for member in structure.members:
            field = StructField(
                name=member.name or f"field_{member.offset:x}",
                offset=member.offset,
                size=member.type.width if member.type else 0,
                type_str=str(member.type) if member.type else "unknown",
                is_pointer=member.type.type_class == bn.TypeClass.PointerTypeClass if member.type else False,
                is_array=member.type.type_class == bn.TypeClass.ArrayTypeClass if member.type else False,
            )

            if field.is_array and member.type:
                field.array_size = member.type.count

            fields.append(field)

        return fields

    def _infer_structure_from_accesses(self, func: Function, param: Variable,
                                       data_flow: Dict) -> List[StructField]:
        """Infer structure layout from memory access patterns"""
        field_accesses = {}  # offset -> (count, size, type_hint)

        # Get HLIL operations safely
        HLIL_ARRAY_INDEX = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX', None)
        HLIL_ARRAY_INDEX_SSA = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX_SSA', None)
        HLIL_DEREF = getattr(bn.HighLevelILOperation, 'HLIL_DEREF', None)
        HLIL_ADD = getattr(bn.HighLevelILOperation, 'HLIL_ADD', None)

        for addr, instrs in data_flow.items():
            for instr in instrs:
                try:
                    # Look for array index or pointer arithmetic
                    array_ops = [op for op in [HLIL_ARRAY_INDEX, HLIL_ARRAY_INDEX_SSA] if op]
                    if array_ops and instr.operation in array_ops:
                        # Try to extract constant offset
                        if hasattr(instr, 'index'):
                            index = instr.index
                            if hasattr(index, 'constant'):
                                offset = index.constant
                                size = instr.size if hasattr(instr, 'size') else 1

                                if offset not in field_accesses:
                                    field_accesses[offset] = [0, size, "unknown"]
                                field_accesses[offset][0] += 1

                    elif HLIL_DEREF and instr.operation == HLIL_DEREF:
                        # Check if dereferencing param + offset
                        if hasattr(instr, 'src'):
                            src = instr.src
                            if HLIL_ADD and src.operation == HLIL_ADD:
                                # Check if one operand is param and other is constant
                                if hasattr(src, 'left') and hasattr(src, 'right'):
                                    left, right = src.left, src.right
                                    if hasattr(right, 'constant'):
                                        offset = right.constant
                                        size = instr.size if hasattr(instr, 'size') else 1

                                        if offset not in field_accesses:
                                            field_accesses[offset] = [0, size, "unknown"]
                                        field_accesses[offset][0] += 1
                except Exception:
                    continue

        # Convert to StructField objects
        fields = []
        for offset, (count, size, type_hint) in sorted(field_accesses.items()):
            field = StructField(
                name=f"field_{offset:x}",
                offset=offset,
                size=size,
                type_str=self._infer_type_from_size(size),
                access_count=count
            )
            fields.append(field)

        return fields

    def _infer_type_from_size(self, size: int) -> str:
        """Infer C type from access size"""
        size_to_type = {
            1: "uint8_t",
            2: "uint16_t",
            4: "uint32_t",
            8: "uint64_t",
        }
        return size_to_type.get(size, f"uint8_t[{size}]")

    def _identify_constraints(self, func: Function, param: Variable,
                             data_flow: Dict) -> List[InputConstraint]:
        """Identify validation checks and constraints on input"""
        constraints = []

        if not func.hlil:
            return constraints

        HLIL_IF = getattr(bn.HighLevelILOperation, 'HLIL_IF', None)

        try:
            # Look for comparison operations involving the parameter
            for block in func.hlil:
                for instr in block:
                    try:
                        if HLIL_IF and instr.operation == HLIL_IF:
                            if hasattr(instr, 'condition'):
                                condition = instr.condition

                                # Check if condition involves our parameter
                                if self._condition_involves_var(condition, param):
                                    constraint = self._extract_constraint_from_condition(
                                        condition, param, instr.address
                                    )
                                    if constraint:
                                        constraints.append(constraint)
                    except Exception:
                        continue

            # Look for magic value comparisons
            magic_constraints = self._find_magic_value_checks(func, param)
            constraints.extend(magic_constraints)
        except Exception:
            pass

        return constraints

    def _condition_involves_var(self, condition, var: Variable) -> bool:
        """Check if condition expression involves variable"""
        return self._instruction_uses_var(condition, var)

    def _extract_constraint_from_condition(self, condition, param: Variable,
                                          address: int) -> Optional[InputConstraint]:
        """Extract constraint from a conditional expression"""
        try:
            # Get comparison operations safely
            HLIL_CMP_E = getattr(bn.HighLevelILOperation, 'HLIL_CMP_E', None)
            HLIL_CMP_NE = getattr(bn.HighLevelILOperation, 'HLIL_CMP_NE', None)
            HLIL_CMP_SLT = getattr(bn.HighLevelILOperation, 'HLIL_CMP_SLT', None)
            HLIL_CMP_ULT = getattr(bn.HighLevelILOperation, 'HLIL_CMP_ULT', None)
            HLIL_CMP_SLE = getattr(bn.HighLevelILOperation, 'HLIL_CMP_SLE', None)
            HLIL_CMP_ULE = getattr(bn.HighLevelILOperation, 'HLIL_CMP_ULE', None)
            HLIL_CMP_SGT = getattr(bn.HighLevelILOperation, 'HLIL_CMP_SGT', None)
            HLIL_CMP_UGT = getattr(bn.HighLevelILOperation, 'HLIL_CMP_UGT', None)
            HLIL_CMP_SGE = getattr(bn.HighLevelILOperation, 'HLIL_CMP_SGE', None)
            HLIL_CMP_UGE = getattr(bn.HighLevelILOperation, 'HLIL_CMP_UGE', None)

            eq_ops = [op for op in [HLIL_CMP_E, HLIL_CMP_NE] if op]
            lt_ops = [op for op in [HLIL_CMP_SLT, HLIL_CMP_ULT, HLIL_CMP_SLE, HLIL_CMP_ULE] if op]
            gt_ops = [op for op in [HLIL_CMP_SGT, HLIL_CMP_UGT, HLIL_CMP_SGE, HLIL_CMP_UGE] if op]

            if eq_ops and condition.operation in eq_ops:
                # Equality check - might be magic value
                if hasattr(condition, 'left') and hasattr(condition, 'right'):
                    left, right = condition.left, condition.right
                    if hasattr(right, 'constant'):
                        return InputConstraint(
                            type=ConstraintType.MAGIC_VALUE,
                            value=right.constant,
                            description=f"Expected value: {hex(right.constant)}",
                            address=address
                        )

            elif lt_ops and condition.operation in lt_ops:
                # Less than check - might be length/range check
                if hasattr(condition, 'left') and hasattr(condition, 'right'):
                    left, right = condition.left, condition.right
                    if hasattr(right, 'constant'):
                        return InputConstraint(
                            type=ConstraintType.LENGTH_CHECK,
                            max_value=right.constant,
                            description=f"Must be <= {right.constant}",
                            address=address
                        )

            elif gt_ops and condition.operation in gt_ops:
                # Greater than check
                if hasattr(condition, 'left') and hasattr(condition, 'right'):
                    left, right = condition.left, condition.right
                    if hasattr(right, 'constant'):
                        return InputConstraint(
                            type=ConstraintType.RANGE_CHECK,
                            min_value=right.constant,
                            description=f"Must be >= {right.constant}",
                            address=address
                        )
        except Exception:
            pass

        return None

    def _find_magic_value_checks(self, func: Function, param: Variable) -> List[InputConstraint]:
        """Find magic value/signature checks"""
        constraints = []

        HLIL_IF = getattr(bn.HighLevelILOperation, 'HLIL_IF', None)
        HLIL_CMP_E = getattr(bn.HighLevelILOperation, 'HLIL_CMP_E', None)
        HLIL_DEREF = getattr(bn.HighLevelILOperation, 'HLIL_DEREF', None)

        try:
            # Look for patterns like: if (*(uint32_t*)buf == 0x12345678)
            # This is a simplified heuristic
            for block in func.hlil if func.hlil else []:
                for instr in block:
                    try:
                        if HLIL_IF and instr.operation == HLIL_IF:
                            if hasattr(instr, 'condition'):
                                condition = instr.condition
                                if HLIL_CMP_E and condition.operation == HLIL_CMP_E:
                                    # Check if comparing dereferenced param to constant
                                    if hasattr(condition, 'left') and hasattr(condition, 'right'):
                                        left = condition.left
                                        right = condition.right

                                        if hasattr(right, 'constant') and right.constant > 0xFFFF:
                                            # Likely a magic value (large constant)
                                            if HLIL_DEREF and left.operation == HLIL_DEREF:
                                                constraints.append(InputConstraint(
                                                    type=ConstraintType.MAGIC_VALUE,
                                                    offset=0,  # Could try to extract offset
                                                    value=right.constant,
                                                    size=left.size if hasattr(left, 'size') else 4,
                                                    description=f"Magic signature: {hex(right.constant)}",
                                                    address=instr.address
                                                ))
                    except Exception:
                        continue
        except Exception:
            pass

        return constraints

    def _infer_size_bounds(self, func: Function, param: Variable,
                          constraints: List[InputConstraint]) -> Tuple[Optional[int], Optional[int]]:
        """Infer minimum and maximum size bounds from constraints"""
        min_size = None
        max_size = None

        for constraint in constraints:
            if constraint.type == ConstraintType.LENGTH_CHECK:
                if constraint.max_value is not None:
                    if max_size is None or constraint.max_value < max_size:
                        max_size = constraint.max_value

            elif constraint.type == ConstraintType.RANGE_CHECK:
                if constraint.min_value is not None:
                    if min_size is None or constraint.min_value > min_size:
                        min_size = constraint.min_value

            elif constraint.type == ConstraintType.MAGIC_VALUE:
                # Magic values imply minimum size
                if constraint.offset is not None and constraint.size:
                    required_size = constraint.offset + constraint.size
                    if min_size is None or required_size > min_size:
                        min_size = required_size

        return min_size, max_size

    def _extract_format_hints(self, func: Function, param: Variable,
                             data_flow: Dict) -> List[str]:
        """Detect hints about input format (JSON, XML, binary, etc.)"""
        hints = []

        # Look for calls to format-specific functions
        format_functions = {
            'json': ['json_parse', 'cJSON_Parse', 'yajl_parse'],
            'xml': ['xmlParseDoc', 'xmlReadMemory', 'XML_Parse'],
            'base64': ['base64_decode', 'EVP_DecodeBlock'],
            'compression': ['uncompress', 'inflate', 'LZ4_decompress'],
            'crypto': ['AES_', 'MD5_', 'SHA256_', 'EVP_Decrypt'],
        }

        for callee in func.callees:
            callee_name = callee.name.lower()
            for format_type, patterns in format_functions.items():
                for pattern in patterns:
                    if pattern.lower() in callee_name:
                        hints.append(format_type)
                        break

        # Look for string comparisons that might indicate format
        HLIL_CALL = getattr(bn.HighLevelILOperation, 'HLIL_CALL', None)
        HLIL_CONST_PTR = getattr(bn.HighLevelILOperation, 'HLIL_CONST_PTR', None)

        try:
            if func.hlil:
                for block in func.hlil:
                    for instr in block:
                        try:
                            if HLIL_CALL and instr.operation == HLIL_CALL:
                                if hasattr(instr, 'dest'):
                                    dest = instr.dest
                                    if HLIL_CONST_PTR and dest.operation == HLIL_CONST_PTR:
                                        callee = self.bv.get_function_at(dest.constant)
                                        if callee and 'strcmp' in callee.name:
                                            # Check arguments for format indicators
                                            # This is simplified - proper implementation would extract string args
                                            hints.append('text')
                        except Exception:
                            continue
        except Exception:
            pass

        return list(set(hints))  # Remove duplicates

    def build_input_grammar(self, spec: InputSpec) -> str:
        """Generate a grammar representation of the input format"""
        grammar_lines = []

        if spec.input_type == "struct" and spec.structure:
            grammar_lines.append("struct {")
            for field in spec.structure:
                grammar_lines.append(f"  {field.type_str} {field.name};  // offset: {hex(field.offset)}")
            grammar_lines.append("}")
        elif spec.input_type == "buffer":
            size_str = ""
            if spec.size:
                size_str = f"[{spec.size}]"
            elif spec.min_size and spec.max_size:
                size_str = f"[{spec.min_size}..{spec.max_size}]"
            elif spec.max_size:
                size_str = f"[0..{spec.max_size}]"

            grammar_lines.append(f"uint8_t buffer{size_str};")

        # Add constraints as comments
        if spec.constraints:
            grammar_lines.append("\n// Constraints:")
            for constraint in spec.constraints:
                grammar_lines.append(f"//   {constraint.description}")

        return "\n".join(grammar_lines)

    def export_spec_json(self, spec: InputSpec) -> Dict:
        """Export InputSpec as JSON-serializable dict"""
        return {
            'input_type': spec.input_type,
            'parameter_index': spec.parameter_index,
            'parameter_name': spec.parameter_name,
            'size': spec.size,
            'min_size': spec.min_size,
            'max_size': spec.max_size,
            'structure': [
                {
                    'name': f.name,
                    'offset': f.offset,
                    'size': f.size,
                    'type': f.type_str,
                    'is_pointer': f.is_pointer,
                    'is_array': f.is_array,
                    'array_size': f.array_size,
                }
                for f in spec.structure
            ],
            'constraints': [
                {
                    'type': c.type.value,
                    'offset': c.offset,
                    'size': c.size,
                    'value': c.value,
                    'min_value': c.min_value,
                    'max_value': c.max_value,
                    'description': c.description,
                    'address': hex(c.address),
                }
                for c in spec.constraints
            ],
            'format_hints': spec.format_hints,
            'grammar': self.build_input_grammar(spec),
        }
