# plugin/core/kafl_integration.py

"""
kAFL Integration Module
Ties together all fuzzing components and provides high-level API
"""

from typing import Dict, List, Optional
import json
import os
from .fuzz_target_analyzer import FuzzTargetAnalyzer, FuzzTarget
from .input_analyzer import InputAnalyzer, InputSpec
from .harness_generator import HarnessGenerator, HarnessConfig, HarnessType
from .seed_generator import SeedGenerator

class KAFLProject:
    """Complete kAFL fuzzing project"""

    def __init__(self, bv, target: FuzzTarget, input_spec: InputSpec):
        self.bv = bv
        self.target = target
        self.input_spec = input_spec

        # Generators
        self.harness_gen = HarnessGenerator(bv)
        self.seed_gen = SeedGenerator(bv)

    def generate(self, output_dir: str, harness_type: str = "kernel",
                 num_seeds: int = 100) -> Dict:
        """Generate complete fuzzing project"""

        # Create directory structure
        os.makedirs(output_dir, exist_ok=True)

        harness_dir = os.path.join(output_dir, 'harness')
        seeds_dir = os.path.join(output_dir, 'seeds')
        docs_dir = os.path.join(output_dir, 'docs')

        os.makedirs(harness_dir, exist_ok=True)
        os.makedirs(seeds_dir, exist_ok=True)
        os.makedirs(docs_dir, exist_ok=True)

        # Generate harness
        harness_config = HarnessConfig(
            target_function=self.target.name,
            target_address=self.target.address,
            input_spec=self.input_spec,
            harness_type=HarnessType(harness_type),
        )

        harness_files = self.harness_gen.generate_harness(harness_config)

        # Write harness files
        for filename, content in harness_files.items():
            filepath = os.path.join(harness_dir, filename)
            with open(filepath, 'w') as f:
                f.write(content)

        # Generate seeds
        seeds = self.seed_gen.generate_seed_corpus(
            self.input_spec,
            num_seeds=num_seeds,
            strategies=["minimal", "boundary", "magic_values", "structured"]
        )

        # Export seeds
        seed_files = self.seed_gen.export_seed_corpus(seeds, seeds_dir)

        # Generate analysis report
        report = self._generate_analysis_report()
        report_path = os.path.join(docs_dir, 'analysis_report.md')
        with open(report_path, 'w') as f:
            f.write(report)

        # Create project manifest
        manifest = {
            'target': {
                'name': self.target.name,
                'address': hex(self.target.address),
                'scores': {
                    'total': self.target.total_score,
                    'complexity': self.target.complexity_score,
                    'input_dependency': self.target.input_dependency_score,
                    'danger': self.target.danger_score,
                },
            },
            'input_spec': {
                'type': self.input_spec.input_type,
                'size_range': f"{self.input_spec.min_size}-{self.input_spec.max_size}",
                'constraints': len(self.input_spec.constraints),
            },
            'harness': {
                'type': harness_type,
                'files': list(harness_files.keys()),
            },
            'seeds': {
                'count': len(seeds),
                'strategies': list(set(s.strategy.value for s in seeds)),
            },
            'directories': {
                'harness': harness_dir,
                'seeds': seeds_dir,
                'docs': docs_dir,
            }
        }

        manifest_path = os.path.join(output_dir, 'project_manifest.json')
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        return manifest

    def _generate_analysis_report(self) -> str:
        """Generate detailed analysis report"""

        report = f'''# kAFL Fuzzing Project Analysis Report

## Target Function: {self.target.name}

**Address**: `{hex(self.target.address)}`

### Fuzzing Potential Scores

| Metric | Score | Description |
|--------|-------|-------------|
| **Total Score** | {self.target.total_score:.3f} | Overall fuzzing value |
| Complexity | {self.target.complexity_score:.3f} | Code complexity |
| Input Dependency | {self.target.input_dependency_score:.3f} | Input handling |
| Danger Score | {self.target.danger_score:.3f} | Vulnerability potential |
| Coverage | {self.target.coverage_score:.3f} | Reachability |

### Function Metrics

- **Basic Blocks**: {self.target.basic_block_count}
- **Cyclomatic Complexity**: {self.target.cyclomatic_complexity}
- **Reachable Functions**: {self.target.reachable_functions}
- **Parameters**: {self.target.parameter_count}
- **Has Loops**: {"Yes" if self.target.has_loops else "No"}
- **Is Exported**: {"Yes" if self.target.is_exported else "No"}

### Input Analysis

**Type**: {self.input_spec.input_type}

**Size Constraints**:
- Minimum: {self.input_spec.min_size or "None"}
- Maximum: {self.input_spec.max_size or "None"}

'''

        if self.input_spec.structure:
            report += "**Structure Definition**:\n\n"
            report += "```c\n"
            report += "typedef struct {\n"
            for field in self.input_spec.structure:
                report += f"    {field.type_str} {field.name};  // offset: {hex(field.offset)}\n"
            report += "} input_struct;\n"
            report += "```\n\n"

        if self.input_spec.constraints:
            report += "### Input Constraints\n\n"
            for i, constraint in enumerate(self.input_spec.constraints, 1):
                report += f"{i}. **{constraint.type.value}**: {constraint.description}\n"
            report += "\n"

        if self.target.input_sources:
            report += "### Input Sources\n\n"
            for source_type, addr in self.target.input_sources:
                report += f"- `{source_type.value}` at `{hex(addr)}`\n"
            report += "\n"

        if self.target.dangerous_ops:
            report += "### Dangerous Operations\n\n"
            op_counts = {}
            for op_type, addr in self.target.dangerous_ops:
                op_name = op_type.value
                if op_name not in op_counts:
                    op_counts[op_name] = []
                op_counts[op_name].append(hex(addr))

            for op_name, addrs in op_counts.items():
                report += f"- **{op_name}**: {len(addrs)} occurrence(s)\n"
                for addr in addrs[:5]:  # Show first 5
                    report += f"  - {addr}\n"
                if len(addrs) > 5:
                    report += f"  - ... and {len(addrs) - 5} more\n"
            report += "\n"

        report += '''
## Fuzzing Strategy Recommendations

### Coverage Goals
- Target high-complexity code paths
- Focus on loops and conditional branches
- Exercise error handling code

### Input Mutation Strategies
- Vary input sizes around boundaries
- Mutate magic values and checksums
- Inject malformed structure fields
- Test with unexpected types

### Monitoring
- Watch for memory corruption (KASAN)
- Monitor assertion failures
- Track coverage growth rate
- Identify crash uniqueness

### Performance Tuning
- Adjust timeout based on function complexity
- Scale threads with available cores
- Enable deterministic mode for reproducibility
- Use grammar-based fuzzing for structured inputs

## Next Steps

1. **Build the harness**: `cd harness && make`
2. **Setup VM environment**: `./harness/setup_vm.sh`
3. **Configure kAFL**: Review and update `harness/kafl.yaml`
4. **Launch fuzzing**: `./harness/run_fuzzer.sh`
5. **Monitor results**: `kafl plot /tmp/kafl_workdir`
6. **Analyze crashes**: `kafl debug /tmp/kafl_workdir/crashes/*`

'''

        return report
