# plugin/core/seed_generator.py

from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import struct
import random
import os
from .input_analyzer import InputSpec, StructField, InputConstraint, ConstraintType

class SeedStrategy(Enum):
    """Seed generation strategies"""
    MINIMAL = "minimal"
    BOUNDARY = "boundary"
    MAGIC_VALUES = "magic_values"
    STRUCTURED = "structured"
    CONSTRAINT_SAT = "constraint_sat"
    MUTATION = "mutation"
    EMBEDDED = "embedded"

@dataclass
class Seed:
    """Represents a generated seed"""
    data: bytes
    name: str
    strategy: SeedStrategy
    description: str
    metadata: Dict = None

class SeedGenerator:
    """Generates seed corpus for fuzzing"""

    def __init__(self, bv):
        self.bv = bv
        self.random = random.Random(42)  # Deterministic seed generation

    def generate_seed_corpus(self,
                            input_spec: InputSpec,
                            num_seeds: int = 100,
                            strategies: List[str] = None) -> List[Seed]:
        """Generate complete seed corpus using multiple strategies"""

        if strategies is None:
            strategies = ["minimal", "boundary", "magic_values", "structured"]

        seeds = []

        # Distribute seeds across strategies
        seeds_per_strategy = max(num_seeds // len(strategies), 1)

        for strategy_name in strategies:
            strategy = SeedStrategy(strategy_name)

            if strategy == SeedStrategy.MINIMAL:
                seeds.extend(self._generate_minimal_seeds(input_spec, seeds_per_strategy))

            elif strategy == SeedStrategy.BOUNDARY:
                seeds.extend(self._generate_boundary_seeds(input_spec, seeds_per_strategy))

            elif strategy == SeedStrategy.MAGIC_VALUES:
                seeds.extend(self._generate_magic_value_seeds(input_spec))

            elif strategy == SeedStrategy.STRUCTURED:
                seeds.extend(self._generate_structured_seeds(input_spec, seeds_per_strategy))

            elif strategy == SeedStrategy.CONSTRAINT_SAT:
                seeds.extend(self._generate_constraint_satisfying_seeds(input_spec, seeds_per_strategy))

            elif strategy == SeedStrategy.MUTATION:
                # Mutate existing seeds
                base_seeds = seeds[:min(10, len(seeds))]
                seeds.extend(self._generate_mutated_seeds(base_seeds, seeds_per_strategy))

            elif strategy == SeedStrategy.EMBEDDED:
                seeds.extend(self._extract_embedded_seeds(input_spec))

        # Deduplicate
        unique_seeds = self._deduplicate_seeds(seeds)

        # Limit to requested count
        return unique_seeds[:num_seeds]

    def _generate_minimal_seeds(self, spec: InputSpec, count: int) -> List[Seed]:
        """Generate minimal valid seeds"""
        seeds = []

        # Empty seed
        seeds.append(Seed(
            data=b'',
            name='empty',
            strategy=SeedStrategy.MINIMAL,
            description='Empty input'
        ))

        # Single byte seeds
        for value in [0x00, 0xFF, 0x41]:  # null, max, 'A'
            seeds.append(Seed(
                data=bytes([value]),
                name=f'single_{value:02x}',
                strategy=SeedStrategy.MINIMAL,
                description=f'Single byte: {hex(value)}'
            ))

        # Small sizes
        for size in [1, 2, 4, 8, 16]:
            if spec.min_size and size < spec.min_size:
                continue
            if spec.max_size and size > spec.max_size:
                continue

            seeds.append(Seed(
                data=b'A' * size,
                name=f'minimal_{size}',
                strategy=SeedStrategy.MINIMAL,
                description=f'Minimal valid input of size {size}'
            ))

        return seeds[:count]

    def _generate_boundary_seeds(self, spec: InputSpec, count: int) -> List[Seed]:
        """Generate boundary value seeds"""
        seeds = []

        # Size boundaries
        if spec.min_size is not None:
            # At minimum
            seeds.append(Seed(
                data=b'\x00' * spec.min_size,
                name=f'size_min_{spec.min_size}',
                strategy=SeedStrategy.BOUNDARY,
                description=f'Minimum size: {spec.min_size}'
            ))

            # Just below minimum
            if spec.min_size > 0:
                seeds.append(Seed(
                    data=b'\x00' * (spec.min_size - 1),
                    name=f'size_below_min_{spec.min_size-1}',
                    strategy=SeedStrategy.BOUNDARY,
                    description=f'Below minimum: {spec.min_size - 1}'
                ))

            # Just above minimum
            seeds.append(Seed(
                data=b'\x00' * (spec.min_size + 1),
                name=f'size_above_min_{spec.min_size+1}',
                strategy=SeedStrategy.BOUNDARY,
                description=f'Above minimum: {spec.min_size + 1}'
            ))

        if spec.max_size is not None:
            # At maximum
            seeds.append(Seed(
                data=b'\xFF' * spec.max_size,
                name=f'size_max_{spec.max_size}',
                strategy=SeedStrategy.BOUNDARY,
                description=f'Maximum size: {spec.max_size}'
            ))

            # Just below maximum
            if spec.max_size > 0:
                seeds.append(Seed(
                    data=b'\xFF' * (spec.max_size - 1),
                    name=f'size_below_max_{spec.max_size-1}',
                    strategy=SeedStrategy.BOUNDARY,
                    description=f'Below maximum: {spec.max_size - 1}'
                ))

        # Integer boundaries (for numeric fields)
        for bits in [8, 16, 32, 64]:
            byte_count = bits // 8

            # Max value
            max_val = (1 << bits) - 1
            seeds.append(Seed(
                data=struct.pack(f'<Q', max_val)[:byte_count],
                name=f'uint{bits}_max',
                strategy=SeedStrategy.BOUNDARY,
                description=f'{bits}-bit max unsigned'
            ))

        return seeds[:count]

    def _generate_magic_value_seeds(self, spec: InputSpec) -> List[Seed]:
        """Generate seeds with common magic values"""
        seeds = []

        # Common file signatures
        magic_values = {
            'PE': b'MZ',
            'ELF': b'\x7fELF',
            'JPEG': b'\xFF\xD8\xFF',
            'PNG': b'\x89PNG\r\n\x1a\n',
            'ZIP': b'PK\x03\x04',
            'PDF': b'%PDF',
        }

        for name, magic in magic_values.items():
            seeds.append(Seed(
                data=magic,
                name=f'magic_{name.lower()}',
                strategy=SeedStrategy.MAGIC_VALUES,
                description=f'{name} file signature'
            ))

        # Extract magic values from constraints
        for constraint in spec.constraints:
            if constraint.type == ConstraintType.MAGIC_VALUE and constraint.value is not None:
                # Create seed with magic value at correct offset
                offset = constraint.offset if constraint.offset else 0
                size = constraint.size if constraint.size else 4

                # Build seed with magic value
                data = bytearray(max(offset + size, spec.min_size if spec.min_size else 0))

                # Write magic value
                if size == 1:
                    struct.pack_into('B', data, offset, constraint.value & 0xFF)
                elif size == 2:
                    struct.pack_into('<H', data, offset, constraint.value & 0xFFFF)
                elif size == 4:
                    struct.pack_into('<I', data, offset, constraint.value & 0xFFFFFFFF)
                elif size == 8:
                    struct.pack_into('<Q', data, offset, constraint.value)

                seeds.append(Seed(
                    data=bytes(data),
                    name=f'constraint_magic_{offset:x}_{constraint.value:x}',
                    strategy=SeedStrategy.MAGIC_VALUES,
                    description=f'Magic value {hex(constraint.value)} at offset {hex(offset)}'
                ))

        return seeds

    def _generate_structured_seeds(self, spec: InputSpec, count: int) -> List[Seed]:
        """Generate seeds following structure definition"""
        seeds = []

        if not spec.structure:
            return seeds

        # Calculate total structure size
        total_size = max(f.offset + f.size for f in spec.structure)

        # Generate various structured inputs
        for i in range(count):
            data = bytearray(total_size)

            # Fill each field with reasonable values
            for field in spec.structure:
                field_data = self._generate_field_value(field, i)
                data[field.offset:field.offset+len(field_data)] = field_data

            seeds.append(Seed(
                data=bytes(data),
                name=f'structured_{i}',
                strategy=SeedStrategy.STRUCTURED,
                description=f'Structured input variant {i}'
            ))

        return seeds

    def _generate_field_value(self, field: StructField, variant: int) -> bytes:
        """Generate value for a structure field"""

        if field.is_pointer:
            # Use null or small address
            return struct.pack('<Q', 0)[:field.size]

        if 'int' in field.type_str.lower():
            # Generate integer value
            if variant == 0:
                value = 0
            elif variant == 1:
                value = (1 << (field.size * 8)) - 1  # Max value
            else:
                value = self.random.randint(0, (1 << (field.size * 8)) - 1)

            if field.size == 1:
                return struct.pack('B', value & 0xFF)
            elif field.size == 2:
                return struct.pack('<H', value & 0xFFFF)
            elif field.size == 4:
                return struct.pack('<I', value & 0xFFFFFFFF)
            elif field.size == 8:
                return struct.pack('<Q', value)

        # Default: random bytes
        return bytes([self.random.randint(0, 255) for _ in range(field.size)])

    def _generate_constraint_satisfying_seeds(self, spec: InputSpec, count: int) -> List[Seed]:
        """Generate seeds that satisfy identified constraints"""
        seeds = []

        # Start with a base template
        base_size = spec.max_size if spec.max_size else (spec.min_size if spec.min_size else 64)

        for i in range(count):
            data = bytearray(base_size)

            # Apply each constraint
            for constraint in spec.constraints:
                if constraint.type == ConstraintType.MAGIC_VALUE:
                    # Set magic value
                    if constraint.offset is not None and constraint.value is not None:
                        offset = constraint.offset
                        size = constraint.size if constraint.size else 4

                        if offset + size <= len(data):
                            if size == 4:
                                struct.pack_into('<I', data, offset, constraint.value)
                            elif size == 2:
                                struct.pack_into('<H', data, offset, constraint.value)
                            elif size == 1:
                                data[offset] = constraint.value & 0xFF

                elif constraint.type == ConstraintType.LENGTH_CHECK:
                    # Ensure length is within bounds
                    if constraint.max_value and len(data) > constraint.max_value:
                        data = data[:constraint.max_value]

                elif constraint.type == ConstraintType.RANGE_CHECK:
                    # Set value within range
                    if constraint.offset is not None and constraint.min_value is not None:
                        value = self.random.randint(constraint.min_value,
                                                   constraint.max_value if constraint.max_value else constraint.min_value + 100)
                        struct.pack_into('<I', data, constraint.offset, value)

            seeds.append(Seed(
                data=bytes(data),
                name=f'constraint_sat_{i}',
                strategy=SeedStrategy.CONSTRAINT_SAT,
                description=f'Constraint-satisfying seed {i}'
            ))

        return seeds

    def _generate_mutated_seeds(self, base_seeds: List[Seed], count: int) -> List[Seed]:
        """Generate seeds by mutating existing seeds"""
        seeds = []

        if not base_seeds:
            return seeds

        mutation_strategies = [
            self._mutate_bit_flip,
            self._mutate_byte_flip,
            self._mutate_byte_insert,
            self._mutate_byte_delete,
        ]

        for i in range(count):
            # Pick random base seed
            base = self.random.choice(base_seeds)

            # Pick random mutation
            mutator = self.random.choice(mutation_strategies)

            # Apply mutation
            mutated_data = mutator(base.data)

            seeds.append(Seed(
                data=mutated_data,
                name=f'mutated_{base.name}_{i}',
                strategy=SeedStrategy.MUTATION,
                description=f'Mutation of {base.name}'
            ))

        return seeds

    def _mutate_bit_flip(self, data: bytes) -> bytes:
        """Flip random bits"""
        if not data:
            return data

        data = bytearray(data)
        num_flips = self.random.randint(1, min(8, len(data)))

        for _ in range(num_flips):
            byte_pos = self.random.randint(0, len(data) - 1)
            bit_pos = self.random.randint(0, 7)
            data[byte_pos] ^= (1 << bit_pos)

        return bytes(data)

    def _mutate_byte_flip(self, data: bytes) -> bytes:
        """Flip random bytes"""
        if not data:
            return data

        data = bytearray(data)
        num_flips = self.random.randint(1, min(4, len(data)))

        for _ in range(num_flips):
            pos = self.random.randint(0, len(data) - 1)
            data[pos] = self.random.randint(0, 255)

        return bytes(data)

    def _mutate_byte_insert(self, data: bytes) -> bytes:
        """Insert random bytes"""
        data = bytearray(data)
        insert_count = self.random.randint(1, 16)
        insert_pos = self.random.randint(0, len(data))

        insert_data = bytes([self.random.randint(0, 255) for _ in range(insert_count)])
        data[insert_pos:insert_pos] = insert_data

        return bytes(data)

    def _mutate_byte_delete(self, data: bytes) -> bytes:
        """Delete random bytes"""
        if len(data) <= 1:
            return data

        data = bytearray(data)
        delete_count = self.random.randint(1, min(16, len(data) - 1))
        delete_pos = self.random.randint(0, len(data) - delete_count)

        del data[delete_pos:delete_pos + delete_count]

        return bytes(data)

    def _extract_embedded_seeds(self, spec: InputSpec) -> List[Seed]:
        """Extract potential test data from binary"""
        seeds = []

        # Look for string constants that might be test inputs
        for string_ref in self.bv.strings:
            string_data = string_ref.value.encode('utf-8')

            # Filter by size constraints
            if spec.min_size and len(string_data) < spec.min_size:
                continue
            if spec.max_size and len(string_data) > spec.max_size:
                continue

            # Only include strings that look like test data
            if len(string_data) > 3 and len(string_data) < 256:
                seeds.append(Seed(
                    data=string_data,
                    name=f'embedded_string_{string_ref.start:x}',
                    strategy=SeedStrategy.EMBEDDED,
                    description=f'String from binary at {hex(string_ref.start)}'
                ))

        return seeds[:50]  # Limit embedded seeds

    def _deduplicate_seeds(self, seeds: List[Seed]) -> List[Seed]:
        """Remove duplicate seeds"""
        seen = set()
        unique = []

        for seed in seeds:
            if seed.data not in seen:
                seen.add(seed.data)
                unique.append(seed)

        return unique

    def export_seed_corpus(self, seeds: List[Seed], output_dir: str) -> Dict[str, str]:
        """Export seeds to directory for kAFL"""
        os.makedirs(output_dir, exist_ok=True)

        exported_files = {}

        for i, seed in enumerate(seeds):
            filename = f"{i:04d}_{seed.name}"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(seed.data)

            exported_files[filename] = filepath

        # Create corpus manifest
        manifest = {
            'total_seeds': len(seeds),
            'strategies': list(set(s.strategy.value for s in seeds)),
            'size_range': {
                'min': min(len(s.data) for s in seeds) if seeds else 0,
                'max': max(len(s.data) for s in seeds) if seeds else 0,
            },
            'seeds': [
                {
                    'name': s.name,
                    'size': len(s.data),
                    'strategy': s.strategy.value,
                    'description': s.description,
                }
                for s in seeds
            ]
        }

        import json
        manifest_path = os.path.join(output_dir, 'corpus_manifest.json')
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)

        return exported_files
