
# kAFL Fuzzing Integration for Binary Ninja MCP

This repository adds advanced fuzzing features to the Binary Ninja MCP framework,
including automatic target identification, harness generation, and seed corpus creation
for hypervisor-based fuzzing with kAFL.

## Overview

The kAFL integration provides:
- **Automated Target Identification**: Intelligent analysis to identify the best fuzzing targets
- **Input Analysis**: Deep data flow analysis to understand input structures and constraints
- **Harness Generation**: Automatic generation of production-ready kAFL C harnesses
- **Seed Generation**: Multi-strategy seed corpus creation
- **Complete Project Export**: One-command generation of ready-to-fuzz projects

## Architecture

The system consists of five core components:

```
┌─────────────────────────────────────────┐
│  1. FuzzTargetAnalyzer                  │
│     - Target identification & scoring   │
│     - Complexity & danger analysis      │
├─────────────────────────────────────────┤
│  2. InputAnalyzer                       │
│     - Data flow analysis                │
│     - Structure inference               │
│     - Constraint extraction             │
├─────────────────────────────────────────┤
│  3. HarnessGenerator                    │
│     - kAFL C code generation            │
│     - Build system generation           │
│     - Configuration files               │
├─────────────────────────────────────────┤
│  4. SeedGenerator                       │
│     - Multi-strategy seed generation    │
│     - Mutation engine                   │
│     - Corpus management                 │
├─────────────────────────────────────────┤
│  5. KAFLIntegration                     │
│     - Project orchestration             │
│     - Complete project export           │
└─────────────────────────────────────────┘
```

## MCP Tools

### 1. identify_fuzz_targets

Identifies and ranks potential fuzzing targets based on multiple criteria.

**Usage:**
```python
identify_fuzz_targets(min_complexity=5, max_targets=20)
```

**Scoring Criteria:**
- **Complexity** (20%): Cyclomatic complexity, basic blocks, instructions
- **Input Dependency** (30%): How much the function depends on external input
- **Danger Score** (30%): Presence of dangerous operations (memcpy, pointer derefs, etc.)
- **Coverage** (20%): Number of reachable functions from this target

**Returns:** JSON report with ranked targets:
```json
{
  "targets": [
    {
      "name": "parse_network_packet",
      "address": "0x401000",
      "scores": {
        "total": 0.825,
        "complexity": 0.750,
        "input_dependency": 0.900,
        "danger": 0.850,
        "coverage": 0.800
      },
      "metrics": {
        "basic_blocks": 45,
        "cyclomatic_complexity": 12,
        "reachable_functions": 150,
        "parameter_count": 2,
        "has_loops": true,
        "is_exported": true
      },
      "input_sources": [
        {"type": "user_copy", "address": "0x401050"},
        {"type": "memory_read", "address": "0x401078"}
      ],
      "dangerous_operations": [
        {"type": "memcpy", "address": "0x4010a0"},
        {"type": "array", "address": "0x4010c5"}
      ]
    }
  ]
}
```

### 2. analyze_function_inputs

Analyzes how a function consumes input data through data flow analysis.

**Usage:**
```python
analyze_function_inputs(function_name="parse_packet", param_index=0)
```

**Returns:** Complete input specification:
```json
{
  "input_type": "struct",
  "parameter_name": "packet_data",
  "min_size": 20,
  "max_size": 1500,
  "structure": [
    {
      "name": "header",
      "offset": 0,
      "size": 4,
      "type": "uint32_t"
    },
    {
      "name": "data",
      "offset": 4,
      "size": 1496,
      "type": "uint8_t[1496]"
    }
  ],
  "constraints": [
    {
      "type": "magic",
      "offset": 0,
      "value": "0x4d5a",
      "description": "Magic signature: 0x4d5a"
    },
    {
      "type": "length",
      "max_value": 1500,
      "description": "Must be <= 1500"
    }
  ],
  "format_hints": ["binary"],
  "grammar": "struct {\n  uint32_t header;\n  uint8_t[1496] data;\n}"
}
```

### 3. find_dangerous_operations

Finds potentially vulnerable operations in code.

**Usage:**
```python
# Analyze single function
find_dangerous_operations(function_name="parse_packet")

# Analyze entire binary
find_dangerous_operations()
```

**Detected Operations:**
- Memory operations: memcpy, strcpy, sprintf
- Memory management: malloc, free, alloca
- Pointer dereferences
- Array accesses (potential OOB)
- Type casts (potential type confusion)
- Arithmetic (potential integer overflow)

### 4. generate_kafl_harness

Generates complete kAFL fuzzing harness with all supporting files.

**Usage:**
```python
# First analyze inputs
input_spec = analyze_function_inputs("parse_packet")

# Then generate harness
generate_kafl_harness(
    target_function="parse_packet",
    input_spec=input_spec,
    harness_type="kernel"
)
```

**Harness Types:**
- `kernel`: Linux kernel module harness
- `userspace`: Userspace executable harness
- `driver`: Device driver harness
- `uefi`: UEFI firmware harness

**Generated Files:**
- `harness.c` - Main C harness with kAFL hypercalls
- `kafl_user.h` - kAFL API definitions
- `input_types.h` - Input structure definitions
- `Makefile` - Build configuration
- `CMakeLists.txt` - CMake configuration
- `kafl.yaml` - kAFL fuzzer configuration
- `README.md` - Documentation
- `run_fuzzer.sh` - Fuzzer launch script
- `setup_vm.sh` - VM setup automation

### 5. generate_seed_corpus

Generates seed corpus using multiple strategies.

**Usage:**
```python
input_spec = analyze_function_inputs("parse_packet")

generate_seed_corpus(
    input_spec=input_spec,
    num_seeds=100,
    strategies=["minimal", "boundary", "magic_values", "structured"]
)
```

**Strategies:**
- **minimal**: Empty and small valid inputs
- **boundary**: Size and value boundaries (0, -1, MAX, etc.)
- **magic_values**: Common file signatures and magic constants
- **structured**: Valid structure instances following the inferred structure
- **constraint_sat**: Seeds satisfying identified constraints
- **mutation**: AFL-style mutations of base seeds
- **embedded**: Test data extracted from the binary

**Returns:** Seed metadata with previews:
```json
{
  "count": 100,
  "seeds": [
    {
      "name": "minimal_4",
      "size": 4,
      "strategy": "minimal",
      "description": "Minimal valid input of size 4",
      "data_preview": "41414141"
    },
    {
      "name": "magic_pe",
      "size": 2,
      "strategy": "magic_values",
      "description": "PE file signature",
      "data_preview": "4d5a"
    }
  ]
}
```

### 6. export_kafl_project

Exports complete, ready-to-use kAFL fuzzing project.

**Usage:**
```python
export_kafl_project(
    target_function="parse_packet",
    output_directory="/tmp/kafl_project",
    include_analysis=True
)
```

**Generated Structure:**
```
output_dir/
├── harness/
│   ├── harness.c
│   ├── kafl_user.h
│   ├── input_types.h
│   ├── Makefile
│   ├── CMakeLists.txt
│   ├── kafl.yaml
│   ├── run_fuzzer.sh
│   └── setup_vm.sh
├── seeds/
│   ├── 0000_empty
│   ├── 0001_minimal_1
│   ├── ...
│   └── corpus_manifest.json
├── docs/
│   └── analysis_report.md
└── project_manifest.json
```

**Analysis Report Includes:**
- Target scoring breakdown
- Function metrics
- Input specification
- Identified constraints
- Dangerous operations
- Fuzzing strategy recommendations
- Step-by-step instructions

## Example

```
User: "Analyze this kernel driver for fuzzing opportunities

refer to this
1. identify_fuzz_targets	GET /fuzzTargets?minComplexity=5&maxTargets=10
2. find_dangerous_operations	GET /dangerousOperations?function=ioctl_handler
3. analyze_function_inputs	GET /analyzeFunctionInputs?name=ioctl_handler&param_index=2
4. generate_kafl_harness	POST /generateHarness
5. generate_seed_corpus	POST /generateSeeds
6. export_kafl_project	POST /exportKaflProject
"

```

## Component Details

### FuzzTargetAnalyzer

**File:** `plugin/core/fuzz_target_analyzer.py`

**Key Features:**
- Identifies entry points (exports, IOCTLs, syscalls)
- Scores targets using weighted metrics
- Tracks input sources and data flow
- Detects dangerous operations
- Estimates coverage potential
- Calculates cyclomatic complexity
- Detects loops and error handling

### InputAnalyzer

**File:** `plugin/core/input_analyzer.py`

**Key Features:**
- Data flow tracing from parameters
- Structure inference from access patterns
- Constraint extraction from comparisons
- Magic value detection
- Size bound inference
- Format hint detection (JSON, XML, binary, etc.)
- Grammar generation for structured inputs

### HarnessGenerator

**File:** `plugin/core/harness_generator.py`

**Key Features:**
- Template-based code generation
- kAFL hypercall integration
- CR3 submission for Intel PT
- KASAN integration for kernel targets
- Panic handler generation
- Input validation code
- Build system generation
- Complete documentation

**kAFL Hypercalls Used:**
- `HYPERCALL_KAFL_ACQUIRE` - Acquire fuzzer control
- `HYPERCALL_KAFL_RELEASE` - Release control
- `HYPERCALL_KAFL_SUBMIT_CR3` - Submit CR3 for tracing
- `HYPERCALL_KAFL_SUBMIT_PANIC` - Set panic handler
- `HYPERCALL_KAFL_SUBMIT_KASAN` - Enable KASAN
- `HYPERCALL_KAFL_GET_PAYLOAD` - Get input buffer
- `HYPERCALL_KAFL_GET_PAYLOAD_SIZE` - Get input size
- `HYPERCALL_KAFL_NEXT_PAYLOAD` - Request next input
- `HYPERCALL_KAFL_RANGE_SUBMIT` - Mark code ranges
- `HYPERCALL_KAFL_PANIC` - Signal crash

### SeedGenerator

**File:** `plugin/core/seed_generator.py`

**Key Features:**
- 7 generation strategies
- Deterministic seed generation
- Automatic deduplication
- Corpus manifest generation
- Strategy-specific metadata
- Binary data extraction
- Mutation engine with multiple strategies

### KAFLIntegration

**File:** `plugin/core/kafl_integration.py`

**Key Features:**
- Complete project orchestration
- Directory structure creation
- File generation and writing
- Manifest creation
- Detailed analysis report generation
- Fuzzing strategy recommendations


## License

> ⚡ This project is a modified and extended version of [Binary Ninja MCP](https://github.com/fosdickio/binary_ninja_mcp),  
> originally developed by fosdickio and licensed under the MIT License.  
> 
> All modifications for kAFL fuzzing integration were developed by ott3r07 (2025).

Original README (upstream): [README.upstream.md](./README.upstream.md)