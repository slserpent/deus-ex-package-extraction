#!/usr/bin/env python3
"""
Deus Ex ConSpeech Search Tool
Searches for text patterns in ConSpeech objects within Deus Ex package files.
"""

import sys
import struct
import re
from pathlib import Path
from typing import List, Tuple, Optional

class CompactIndexReader:
    """Handles reading CompactIndex encoded values."""
    
    @staticmethod
    def read(data: bytes, offset: int) -> Tuple[int, int]:
        """
        Read a CompactIndex value from data at offset.
        Returns (value, new_offset).
        """
        first_byte = data[offset]
        offset += 1
        
        is_negative = (first_byte & 0x80) != 0
        has_continuation = (first_byte & 0x40) != 0
        value = first_byte & 0x3F
        
        if not has_continuation:
            return (-value if is_negative else value, offset)
        
        shift = 6
        for byte_num in range(1, 5):
            next_byte = data[offset]
            offset += 1
            
            has_continuation = (next_byte & 0x80) != 0
            byte_value = next_byte & 0x7F if byte_num < 4 else next_byte
            
            value |= (byte_value << shift)
            shift += 7 if byte_num < 4 else 8
            
            if not has_continuation or byte_num == 4:
                break
        
        return (-value if is_negative else value, offset)


class DeusExPackage:
    """Parser for Deus Ex package files."""
    
    SIGNATURE = 0x9E2A83C1
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.names = []
        self.imports = []
        self.exports = []
        
    def load(self):
        """Load and parse the package file."""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()
        
        # Verify signature
        sig = struct.unpack('<I', self.data[0:4])[0]
        if sig != self.SIGNATURE:
            raise ValueError(f"Invalid package signature: {hex(sig)}")
        
        # Read header
        name_count = struct.unpack('<I', self.data[0x0C:0x10])[0]
        name_offset = struct.unpack('<I', self.data[0x10:0x14])[0]
        export_count = struct.unpack('<I', self.data[0x14:0x18])[0]
        export_offset = struct.unpack('<I', self.data[0x18:0x1C])[0]
        import_count = struct.unpack('<I', self.data[0x1C:0x20])[0]
        import_offset = struct.unpack('<I', self.data[0x20:0x24])[0]
        
        # Parse tables
        self._parse_name_table(name_offset, name_count)
        self._parse_import_table(import_offset, import_count)
        self._parse_export_table(export_offset, export_count)
    
    def _parse_name_table(self, offset: int, count: int):
        """Parse the name table."""
        for _ in range(count):
            str_len = self.data[offset]
            offset += 1
            name = self.data[offset:offset + str_len - 1].decode('ascii', errors='ignore')
            offset += str_len
            offset += 4  # Skip flags
            self.names.append(name)
    
    def _parse_import_table(self, offset: int, count: int):
        """Parse the import table."""
        for _ in range(count):
            class_package, offset = CompactIndexReader.read(self.data, offset)
            class_name, offset = CompactIndexReader.read(self.data, offset)
            offset += 4  # Skip package DWORD
            object_name, offset = CompactIndexReader.read(self.data, offset)
            
            self.imports.append({
                'class_package': class_package,
                'class_name': class_name,
                'object_name': object_name
            })
    
    def _parse_export_table(self, offset: int, count: int):
        """Parse the export table."""
        for _ in range(count):
            class_ref, offset = CompactIndexReader.read(self.data, offset)
            super_ref, offset = CompactIndexReader.read(self.data, offset)
            group = struct.unpack('<I', self.data[offset:offset+4])[0]
            offset += 4
            object_name, offset = CompactIndexReader.read(self.data, offset)
            object_flags = struct.unpack('<I', self.data[offset:offset+4])[0]
            offset += 4
            serial_size, offset = CompactIndexReader.read(self.data, offset)
            
            serial_offset = 0
            if serial_size > 0:
                serial_offset, offset = CompactIndexReader.read(self.data, offset)
            
            self.exports.append({
                'class': class_ref,
                'super': super_ref,
                'group': group,
                'object_name': object_name,
                'object_flags': object_flags,
                'serial_size': serial_size,
                'serial_offset': serial_offset
            })
    
    def get_class_name(self, export_idx: int) -> str:
        """Get the class name for an export entry."""
        export = self.exports[export_idx]
        class_ref = export['class']
        
        if class_ref < 0:
            # Reference to import table
            import_idx = -class_ref - 1
            if import_idx < len(self.imports):
                name_idx = self.imports[import_idx]['object_name']
                if name_idx < len(self.names):
                    return self.names[name_idx]
        elif class_ref > 0:
            # Reference to export table
            export_idx = class_ref - 1
            if export_idx < len(self.exports):
                name_idx = self.exports[export_idx]['object_name']
                if name_idx < len(self.names):
                    return self.names[name_idx]
        
        return "Unknown"
    
    def get_object_name(self, export_idx: int) -> str:
        """Get the instance name for an export entry."""
        export = self.exports[export_idx]
        name_idx = export['object_name']
        if name_idx < len(self.names):
            return self.names[name_idx]
        return "Unknown"
    
    def parse_properties(self, export_idx: int) -> dict:
        """Parse properties from an export's object data."""
        export = self.exports[export_idx]
        if export['serial_size'] == 0:
            return {}
        
        offset = export['serial_offset']
        end_offset = offset + export['serial_size']
        properties = {}
        
        while offset < end_offset:
            # Read property name index
            prop_name_idx, offset = CompactIndexReader.read(self.data, offset)
            if prop_name_idx >= len(self.names):
                break
            
            prop_name = self.names[prop_name_idx]
            if prop_name.lower() == 'none':
                break
            
            # Read flags byte
            flags = self.data[offset]
            offset += 1
            
            prop_type = flags & 0x0F
            has_array_index = (flags & 0x80) != 0
            
            # Bits 4-6 encode size information (3 bits, values 0-7)
            info_size = (flags >> 4) & 0x07
            
            # Size encoding based on info_size value:
            # 0 = fixed 1 byte
            # 1 = fixed 2 bytes
            # 2 = fixed 4 bytes
            # 3 = fixed 12 bytes
            # 4 = fixed 16 bytes
            # 5 = variable, read 1 byte for size
            # 6 = variable, read 2 bytes (word) for size
            # 7 = variable, read 4 bytes (dword) for size
            
            property_size = 0
            if info_size == 0:
                property_size = 1
            elif info_size == 1:
                property_size = 2
            elif info_size == 2:
                property_size = 4
            elif info_size == 3:
                property_size = 12
            elif info_size == 4:
                property_size = 16
            elif info_size == 5:
                property_size = self.data[offset]
                offset += 1
            elif info_size == 6:
                property_size = struct.unpack('<H', self.data[offset:offset+2])[0]
                offset += 2
            elif info_size == 7:
                property_size = struct.unpack('<I', self.data[offset:offset+4])[0]
                offset += 4
            
            # Handle array index if present
            if has_array_index:
                array_index = self.data[offset]
                offset += 1
            
            # Parse property data based on type
            if prop_type == 0x0D:  # String type (otStr)
                # String length is encoded as CompactIndex
                str_len, offset = CompactIndexReader.read(self.data, offset)
                if str_len > 0:
                    value = self.data[offset:offset + str_len].decode('ascii', errors='ignore')
                    # Remove trailing null terminators
                    value = value.rstrip('\x00')
                    offset += str_len
                    properties[prop_name] = value
                    
                    # Assuming Speech is first property, we can return early
                    if prop_name == 'Speech':
                        return properties
            else:
                # Skip unknown property types
                # If we have property_size, use it; otherwise guess
                if has_property_size:
                    offset += property_size
                else:
                    offset += 4
        
        return properties


def load_search_terms(filepath: str) -> List[List[str]]:
    """Load search term groups from file."""
    term_groups = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                terms = [t.strip() for t in line.split('\t') if t.strip()]
                if terms:
                    term_groups.append(terms)
    return term_groups


def search_speech(package: DeusExPackage, term_groups: List[List[str]]):
    """Search for term groups in ConSpeech objects."""
    # Find all ConSpeech objects
    conspeech_objects = []
    for idx, export in enumerate(package.exports):
        class_name = package.get_class_name(idx)
        if class_name == "ConSpeech":
            conspeech_objects.append(idx)
    
    print(f"Found {len(conspeech_objects)} ConSpeech objects\n")
    
    # Search each term group
    for term_group in term_groups:
        matches_found = False
        
        for export_idx in conspeech_objects:
            props = package.parse_properties(export_idx)
            speech = props.get('Speech', '')
            
            if not speech:
                continue
            
            # Check if all terms in group are in speech with word boundaries
            # Use negative lookbehind/lookahead for [a-z0-9]
            all_match = True
            for term in term_group:
                # Create pattern with word boundaries
                pattern = r'(?<![a-z0-9])' + re.escape(term) + r'(?![a-z0-9])'
                if not re.search(pattern, speech, re.IGNORECASE):
                    all_match = False
                    break
            
            if all_match:
                instance_name = package.get_object_name(export_idx)
                term_str = ' + '.join(term_group)
                
                print(f"Instance: {instance_name}")
                print(f"Terms: {term_str}")
                print(f"Speech: {speech}")
                print("-" * 80)
                matches_found = True
        
        if not matches_found:
            term_str = ' + '.join(term_group)
            print(f"No matches for: {term_str}")
            print("-" * 80)


def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <package_file> <search_terms_file>")
        sys.exit(1)
    
    package_path = sys.argv[1]
    terms_path = sys.argv[2]
    
    # Load package
    print(f"Loading package: {package_path}")
    package = DeusExPackage(package_path)
    package.load()
    print(f"Loaded {len(package.names)} names, {len(package.imports)} imports, {len(package.exports)} exports\n")
    
    # Load search terms
    print(f"Loading search terms: {terms_path}")
    term_groups = load_search_terms(terms_path)
    print(f"Loaded {len(term_groups)} search term groups\n")
    
    # Search
    search_speech(package, term_groups)


if __name__ == "__main__":
    main()