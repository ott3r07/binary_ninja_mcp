# plugin/core/fuzz_target_analyzer.py

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import binaryninja as bn
from binaryninja import BinaryView, Function, HighLevelILInstruction
from enum import Enum

class InputSourceType(Enum):
    """Types of input sources that can be fuzzed"""
    MEMORY_READ = "memory_read"
    FILE_READ = "file_read"
    NETWORK_RECV = "network_recv"
    USER_COPY = "user_copy"  # copy_from_user, etc.
    IOCTL = "ioctl"
    SYSCALL = "syscall"
    EXPORTED_FUNCTION = "exported"
    UNKNOWN = "unknown"

class DangerousOperation(Enum):
    """Potentially vulnerable operations"""
    MEMORY_COPY = "memcpy"
    STRING_COPY = "strcpy"
    SPRINTF = "sprintf"
    ALLOCATION = "malloc"
    FREE = "free"
    POINTER_DEREF = "deref"
    ARRAY_ACCESS = "array"
    TYPE_CAST = "cast"
    ARITHMETIC = "arithmetic"

@dataclass
class FuzzTarget:
    """Represents a potential fuzzing target"""
    function: Function
    name: str
    address: int

    # Scoring components
    complexity_score: float
    input_dependency_score: float
    danger_score: float
    coverage_score: float
    total_score: float

    # Analysis details
    input_sources: List[Tuple[InputSourceType, int]]  # (type, address)
    dangerous_ops: List[Tuple[DangerousOperation, int]]
    reachable_functions: int
    basic_block_count: int
    cyclomatic_complexity: int
    call_depth: int

    # Metadata
    is_exported: bool
    has_xrefs: bool
    parameter_count: int
    has_loops: bool
    has_error_handling: bool

class FuzzTargetAnalyzer:
    """Analyzes binaries to identify and rank fuzzing targets"""

    def __init__(self, bv: BinaryView):
        self.bv = bv

        # Scoring weights
        self.complexity_weight = 0.2
        self.input_weight = 0.3
        self.danger_weight = 0.3
        self.coverage_weight = 0.2

        # Known dangerous function patterns
        self.dangerous_functions = {
            'memcpy': DangerousOperation.MEMORY_COPY,
            'strcpy': DangerousOperation.STRING_COPY,
            'strncpy': DangerousOperation.STRING_COPY,
            'sprintf': DangerousOperation.SPRINTF,
            'snprintf': DangerousOperation.SPRINTF,
            'malloc': DangerousOperation.ALLOCATION,
            'calloc': DangerousOperation.ALLOCATION,
            'realloc': DangerousOperation.ALLOCATION,
            'free': DangerousOperation.FREE,
            'alloca': DangerousOperation.ALLOCATION,
        }

        # Kernel-specific patterns
        self.kernel_input_functions = {
            'copy_from_user': InputSourceType.USER_COPY,
            'get_user': InputSourceType.USER_COPY,
            '__get_user': InputSourceType.USER_COPY,
            'strncpy_from_user': InputSourceType.USER_COPY,
            'recv': InputSourceType.NETWORK_RECV,
            'recvfrom': InputSourceType.NETWORK_RECV,
            'read': InputSourceType.FILE_READ,
            'vfs_read': InputSourceType.FILE_READ,
        }

    def identify_entry_points(self) -> List[Function]:
        """Find potential fuzzing entry points"""
        entry_points = []

        # 1. Exported functions
        for symbol in self.bv.get_symbols():
            if symbol.type in [bn.SymbolType.FunctionSymbol,
                              bn.SymbolType.ExportedFunctionSymbol]:
                func = self.bv.get_function_at(symbol.address)
                if func:
                    entry_points.append(func)

        # 2. Functions with external references
        for func in self.bv.functions:
            refs = self.bv.get_code_refs(func.start)
            if len(list(refs)) > 0:
                entry_points.append(func)

        # 3. IOCTL handlers (kernel-specific)
        ioctl_handlers = self._find_ioctl_handlers()
        entry_points.extend(ioctl_handlers)

        # 4. Syscall handlers
        syscall_handlers = self._find_syscall_handlers()
        entry_points.extend(syscall_handlers)

        # Remove duplicates
        return list(set(entry_points))

    def _find_ioctl_handlers(self) -> List[Function]:
        """Find IOCTL handler functions in kernel drivers"""
        handlers = []

        # Look for file_operations or device_operations structures
        for data_var in self.bv.data_vars:
            var_type = data_var.type
            if var_type and 'file_operations' in str(var_type):
                # Read the structure and extract ioctl pointer
                data = self.bv.read(data_var.address, var_type.width)
                if not data:
                    continue
                # Parse structure (platform-specific offset)
                # Typically ioctl is at offset 0x10 or 0x18
                for offset in [0x10, 0x18, 0x20]:
                    if offset + 8 > len(data):
                        continue
                    ptr_bytes = data[offset:offset+8]  # 64-bit pointer
                    if len(ptr_bytes) == 8:
                        ptr_addr = int.from_bytes(ptr_bytes, 'little')
                        if ptr_addr > 0x1000:  # Sanity check
                            func = self.bv.get_function_at(ptr_addr)
                            if func:
                                handlers.append(func)

        return handlers

    def _find_syscall_handlers(self) -> List[Function]:
        """Find syscall handler functions"""
        handlers = []

        # Look for syscall table references
        # Pattern: sys_call_table or similar names
        for symbol in self.bv.get_symbols():
            if 'syscall' in symbol.name.lower() or 'sys_call' in symbol.name.lower():
                # This might be a syscall table
                if symbol.type == bn.SymbolType.DataSymbol:
                    # Read table entries
                    table_addr = symbol.address
                    for i in range(512):  # Max syscalls
                        entry_addr = table_addr + (i * 8)  # 64-bit entries
                        func_ptr_bytes = self.bv.read(entry_addr, 8)
                        if func_ptr_bytes:
                            func_addr = int.from_bytes(func_ptr_bytes, 'little')
                            if func_addr > 0x1000:  # Sanity check
                                func = self.bv.get_function_at(func_addr)
                                if func:
                                    handlers.append(func)

        return handlers

    def analyze_input_sources(self, func: Function) -> List[Tuple[InputSourceType, int]]:
        """Detect how function receives input data"""
        input_sources = []

        if not func.hlil:
            return input_sources

        # Get HLIL operation enums safely
        HLIL_CALL = getattr(bn.HighLevelILOperation, 'HLIL_CALL', None)
        HLIL_CONST_PTR = getattr(bn.HighLevelILOperation, 'HLIL_CONST_PTR', None)
        HLIL_DEREF = getattr(bn.HighLevelILOperation, 'HLIL_DEREF', None)
        HLIL_ARRAY_INDEX = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX', None)
        HLIL_ARRAY_INDEX_SSA = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX_SSA', None)

        try:
            # Scan HLIL for input-related operations
            for block in func.hlil:
                for instr in block:
                    try:
                        # Check for calls to known input functions
                        if HLIL_CALL and instr.operation == HLIL_CALL:
                            dest = instr.dest
                            if HLIL_CONST_PTR and dest.operation == HLIL_CONST_PTR:
                                callee = self.bv.get_function_at(dest.constant)
                                if callee:
                                    callee_name = callee.name
                                    for pattern, source_type in self.kernel_input_functions.items():
                                        if pattern in callee_name:
                                            input_sources.append((source_type, instr.address))

                        # Check for memory reads from parameters
                        if HLIL_DEREF and instr.operation == HLIL_DEREF:
                            src = instr.src
                            if self._is_parameter_derived(src, func):
                                input_sources.append((InputSourceType.MEMORY_READ, instr.address))

                        # Check for array accesses on parameters
                        array_ops = [op for op in [HLIL_ARRAY_INDEX, HLIL_ARRAY_INDEX_SSA] if op]
                        if array_ops and instr.operation in array_ops:
                            if hasattr(instr, 'src') and self._is_parameter_derived(instr.src, func):
                                input_sources.append((InputSourceType.MEMORY_READ, instr.address))
                    except Exception:
                        continue
        except Exception:
            pass

        return input_sources

    def _is_parameter_derived(self, expr: HighLevelILInstruction, func: Function) -> bool:
        """Check if expression is derived from function parameters"""
        try:
            HLIL_VAR = getattr(bn.HighLevelILOperation, 'HLIL_VAR', None)

            if HLIL_VAR and expr.operation == HLIL_VAR:
                # Check if variable is a parameter
                var = expr.var
                for param in func.parameter_vars:
                    if param == var:
                        return True

            # Recursively check operands
            if hasattr(expr, 'operands'):
                for operand in expr.operands:
                    if isinstance(operand, HighLevelILInstruction):
                        if self._is_parameter_derived(operand, func):
                            return True
        except Exception:
            pass

        return False

    def find_dangerous_operations(self, func: Function) -> List[Tuple[DangerousOperation, int]]:
        """Find potentially dangerous operations in function"""
        dangerous_ops = []

        if not func.hlil:
            return dangerous_ops

        # Get HLIL operation enums safely
        HLIL_CALL = getattr(bn.HighLevelILOperation, 'HLIL_CALL', None)
        HLIL_CONST_PTR = getattr(bn.HighLevelILOperation, 'HLIL_CONST_PTR', None)
        HLIL_DEREF = getattr(bn.HighLevelILOperation, 'HLIL_DEREF', None)
        HLIL_ARRAY_INDEX = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX', None)
        HLIL_ARRAY_INDEX_SSA = getattr(bn.HighLevelILOperation, 'HLIL_ARRAY_INDEX_SSA', None)
        HLIL_CAST = getattr(bn.HighLevelILOperation, 'HLIL_CAST', None)
        HLIL_ADD = getattr(bn.HighLevelILOperation, 'HLIL_ADD', None)
        HLIL_SUB = getattr(bn.HighLevelILOperation, 'HLIL_SUB', None)
        HLIL_MUL = getattr(bn.HighLevelILOperation, 'HLIL_MUL', None)
        HLIL_DIVU = getattr(bn.HighLevelILOperation, 'HLIL_DIVU', None)
        HLIL_DIVS = getattr(bn.HighLevelILOperation, 'HLIL_DIVS', None)

        try:
            for block in func.hlil:
                for instr in block:
                    try:
                        # Check for calls to dangerous functions
                        if HLIL_CALL and instr.operation == HLIL_CALL:
                            dest = instr.dest
                            if HLIL_CONST_PTR and dest.operation == HLIL_CONST_PTR:
                                callee = self.bv.get_function_at(dest.constant)
                                if callee:
                                    for pattern, op_type in self.dangerous_functions.items():
                                        if pattern in callee.name:
                                            dangerous_ops.append((op_type, instr.address))

                        # Check for pointer dereferences
                        if HLIL_DEREF and instr.operation == HLIL_DEREF:
                            dangerous_ops.append((DangerousOperation.POINTER_DEREF, instr.address))

                        # Check for array accesses (potential OOB)
                        if HLIL_ARRAY_INDEX and HLIL_ARRAY_INDEX_SSA:
                            if instr.operation in [HLIL_ARRAY_INDEX, HLIL_ARRAY_INDEX_SSA]:
                                dangerous_ops.append((DangerousOperation.ARRAY_ACCESS, instr.address))

                        # Check for type casts (potential type confusion)
                        if HLIL_CAST and instr.operation == HLIL_CAST:
                            dangerous_ops.append((DangerousOperation.TYPE_CAST, instr.address))

                        # Check for arithmetic operations (potential integer overflow)
                        arith_ops = [op for op in [HLIL_ADD, HLIL_SUB, HLIL_MUL, HLIL_DIVU, HLIL_DIVS] if op]
                        if arith_ops and instr.operation in arith_ops:
                            dangerous_ops.append((DangerousOperation.ARITHMETIC, instr.address))
                    except Exception:
                        # Skip instructions that cause errors
                        continue
        except Exception:
            # If HLIL iteration fails, return what we have
            pass

        return dangerous_ops

    def calculate_complexity_score(self, func: Function) -> Tuple[float, Dict]:
        """Calculate complexity score for function"""
        metrics = {
            'basic_blocks': len(list(func.basic_blocks)),
            'cyclomatic_complexity': self._calculate_cyclomatic_complexity(func),
            'instruction_count': sum(len(bb) for bb in func.basic_blocks),
            'call_count': len(list(func.callees)),
            'has_loops': self._has_loops(func),
        }

        # Normalize and weight metrics
        score = (
            min(metrics['basic_blocks'] / 50.0, 1.0) * 0.3 +
            min(metrics['cyclomatic_complexity'] / 20.0, 1.0) * 0.4 +
            min(metrics['instruction_count'] / 200.0, 1.0) * 0.2 +
            (1.0 if metrics['has_loops'] else 0.0) * 0.1
        )

        return score, metrics

    def _calculate_cyclomatic_complexity(self, func: Function) -> int:
        """Calculate cyclomatic complexity: E - N + 2P"""
        edges = 0
        nodes = len(list(func.basic_blocks))

        for bb in func.basic_blocks:
            edges += len(bb.outgoing_edges)

        # P = 1 for single connected component
        complexity = edges - nodes + 2
        return max(complexity, 1)

    def _has_loops(self, func: Function) -> bool:
        """Detect if function contains loops"""
        # Check for back edges in CFG
        visited = set()
        rec_stack = set()

        def has_cycle(bb):
            visited.add(bb.start)
            rec_stack.add(bb.start)

            for edge in bb.outgoing_edges:
                target = edge.target.start
                if target not in visited:
                    if has_cycle(edge.target):
                        return True
                elif target in rec_stack:
                    return True

            rec_stack.remove(bb.start)
            return False

        for bb in func.basic_blocks:
            if bb.start not in visited:
                if has_cycle(bb):
                    return True

        return False

    def estimate_coverage_potential(self, func: Function) -> Tuple[float, int]:
        """Estimate reachable code from this function"""
        reachable = set()
        to_visit = [func]

        while to_visit:
            current = to_visit.pop()
            if current.start in reachable:
                continue

            reachable.add(current.start)

            # Add callees (limit depth to avoid explosion)
            if len(reachable) < 1000:  # Depth limit
                for callee in current.callees:
                    if callee.start not in reachable:
                        to_visit.append(callee)

        # Score based on reachable functions
        total_functions = len(list(self.bv.functions))
        coverage_ratio = len(reachable) / max(total_functions, 1)
        score = min(coverage_ratio * 10, 1.0)  # Scale up but cap at 1.0

        return score, len(reachable)

    def analyze_function(self, func: Function) -> FuzzTarget:
        """Perform complete analysis on a single function"""
        # Input analysis
        input_sources = self.analyze_input_sources(func)
        input_score = min(len(input_sources) / 5.0, 1.0)

        # Danger analysis
        dangerous_ops = self.find_dangerous_operations(func)
        danger_score = min(len(dangerous_ops) / 10.0, 1.0)

        # Complexity analysis
        complexity_score, complexity_metrics = self.calculate_complexity_score(func)

        # Coverage analysis
        coverage_score, reachable_count = self.estimate_coverage_potential(func)

        # Calculate total score
        total_score = (
            self.complexity_weight * complexity_score +
            self.input_weight * input_score +
            self.danger_weight * danger_score +
            self.coverage_weight * coverage_score
        )

        # Check metadata
        is_exported = False
        try:
            # Try to use ExportedFunctionSymbol if available
            exported_type = getattr(bn.SymbolType, 'ExportedFunctionSymbol', None)
            if exported_type:
                is_exported = any(
                    sym.address == func.start and sym.type == exported_type
                    for sym in self.bv.get_symbols()
                )
            else:
                # Fallback: check if function name is in exports
                is_exported = any(
                    sym.address == func.start
                    for sym in self.bv.get_symbols()
                    if hasattr(sym, 'binding') and sym.binding
                )
        except Exception:
            # If all else fails, just check if it has a symbol
            is_exported = self.bv.get_symbol_at(func.start) is not None

        has_xrefs = len(list(self.bv.get_code_refs(func.start))) > 0

        return FuzzTarget(
            function=func,
            name=func.name,
            address=func.start,
            complexity_score=complexity_score,
            input_dependency_score=input_score,
            danger_score=danger_score,
            coverage_score=coverage_score,
            total_score=total_score,
            input_sources=input_sources,
            dangerous_ops=dangerous_ops,
            reachable_functions=reachable_count,
            basic_block_count=complexity_metrics['basic_blocks'],
            cyclomatic_complexity=complexity_metrics['cyclomatic_complexity'],
            call_depth=len(list(func.callees)),
            is_exported=is_exported,
            has_xrefs=has_xrefs,
            parameter_count=len(func.parameter_vars),
            has_loops=complexity_metrics['has_loops'],
            has_error_handling=self._has_error_handling(func)
        )

    def _has_error_handling(self, func: Function) -> bool:
        """Detect basic error handling patterns"""
        if not func.hlil:
            return False

        for block in func.hlil:
            for instr in block:
                # Look for comparisons followed by early returns
                if instr.operation == bn.HighLevelILOperation.HLIL_IF:
                    condition = instr.condition
                    # Check if condition involves comparisons
                    if condition.operation in [
                        bn.HighLevelILOperation.HLIL_CMP_E,
                        bn.HighLevelILOperation.HLIL_CMP_NE,
                        bn.HighLevelILOperation.HLIL_CMP_SLT,
                        bn.HighLevelILOperation.HLIL_CMP_ULT,
                    ]:
                        return True

        return False

    def rank_targets(self,
                    min_complexity: int = 5,
                    max_targets: int = 20) -> List[FuzzTarget]:
        """Identify, analyze, and rank all fuzzing targets"""
        entry_points = self.identify_entry_points()

        targets = []
        for func in entry_points:
            # Filter by minimum complexity
            if len(list(func.basic_blocks)) < min_complexity:
                continue

            target = self.analyze_function(func)
            targets.append(target)

        # Sort by total score (descending)
        targets.sort(key=lambda t: t.total_score, reverse=True)

        # Return top N targets
        return targets[:max_targets]

    def export_target_report(self, targets: List[FuzzTarget]) -> Dict:
        """Export analysis results as structured data"""
        return {
            'targets': [
                {
                    'name': t.name,
                    'address': hex(t.address),
                    'scores': {
                        'total': round(t.total_score, 3),
                        'complexity': round(t.complexity_score, 3),
                        'input_dependency': round(t.input_dependency_score, 3),
                        'danger': round(t.danger_score, 3),
                        'coverage': round(t.coverage_score, 3),
                    },
                    'metrics': {
                        'basic_blocks': t.basic_block_count,
                        'cyclomatic_complexity': t.cyclomatic_complexity,
                        'reachable_functions': t.reachable_functions,
                        'parameter_count': t.parameter_count,
                        'has_loops': t.has_loops,
                        'is_exported': t.is_exported,
                    },
                    'input_sources': [
                        {'type': src[0].value, 'address': hex(src[1])}
                        for src in t.input_sources
                    ],
                    'dangerous_operations': [
                        {'type': op[0].value, 'address': hex(op[1])}
                        for op in t.dangerous_ops
                    ],
                }
                for t in targets
            ]
        }
