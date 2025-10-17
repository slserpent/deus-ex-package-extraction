# Deus Ex Package File Format Documentation

## Overview

Deus Ex uses the Unreal Engine 1 package format to store game assets including maps (.dx files), textures, sounds, saves, and code. This document details the binary structure of these package files based on some pascal code by Antonio Cordero Balcázar (acordero.org), UnrealWiki Package File Format documentation, and a little reverse engineering.

## File Signature

All Deus Ex package files begin with a 4-byte signature:
```
0xC1 0x83 0x2A 0x9E
```

This signature identifies the file as an Unreal Engine package and should be verified before attempting to parse the file.

## Package Header

The package header is located at offset 0 and contains pointers to the three main data tables.

| Offset | Type  | Field              | Description                                      |
|--------|-------|--------------------|--------------------------------------------------|
| 0x00   | DWORD | Signature          | Always 0x9E2A83C1 (little-endian)               |
| 0x04   | WORD  | Package Version    | File format version (61-69 for UE1)             |
| 0x06   | WORD  | License Mode       | Game-specific license identifier                |
| 0x08   | DWORD | Package Flags      | Global package flags                            |
| 0x0C   | DWORD | Name Count         | Number of entries in name table                 |
| 0x10   | DWORD | Name Table Offset  | Absolute offset to name table                   |
| 0x14   | DWORD | Export Count       | Number of entries in export table               |
| 0x18   | DWORD | Export Table Offset| Absolute offset to export table                 |
| 0x1C   | DWORD | Import Count       | Number of entries in import table               |
| 0x20   | DWORD | Import Table Offset| Absolute offset to import table                 |

*Note: All multi-byte numeric values use little-endian byte order.*

## CompactIndex Format

CompactIndex is a variable-length integer encoding used throughout the package format to save space. It can represent both positive and negative values and uses 1-5 bytes depending on the magnitude.

### Encoding Structure

**First Byte:**
- Bit 7 (0x80): Sign flag (1 = negative)
- Bit 6 (0x40): Continuation flag (1 = more bytes follow)
- Bits 5-0 (0x3F): Lower 6 bits of value

**Bytes 2-4 (if continuation flag set):**
- Bit 7 (0x80): Continuation flag (1 = more bytes follow)
- Bits 6-0 (0x7F): Next 7 bits of value

**Byte 5 (if reached):**
- All 8 bits: Final 8 bits of value (no continuation flag)

### Decoding Algorithm

```python
def read_compact_index(data, offset):
    first_byte = data[offset]
    offset += 1
    
    is_negative = (first_byte & 0x80) != 0
    has_continuation = (first_byte & 0x40) != 0
    value = first_byte & 0x3F
    
    if not has_continuation:
        return -value if is_negative else value, offset
    
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
    
    return -value if is_negative else value, offset
```

### CompactIndex as Simple Integers

CompactIndex encoding is used for simple integer values and also for object references. Beware that values of 0-63 fit in a single byte and appear identical to normal byte values. Larger values use multiple bytes with the continuation bit pattern.

**Examples:**
- Value 5 → `0x05` (one byte)
- Value 63 → `0x3F` (one byte)
- Value 64 → `0xC0 0x01` (two bytes)
- Value 190 → `0x7E 0x02` (two bytes)

### ObjectReference Format

CompactIndex values can also be used as ObjectReferences that point to objects in different tables:

- **Negative values**: Reference to import table (e.g., -1 points to imports[0])
- **Positive values**: Reference to export table (e.g., 3 points to exports[2])
- **Zero**: Null reference (no object)

## Name Table

The name table stores all unique string identifiers used throughout the package. Each entry consists of a Pascal-style string followed by flag data.

### Name Entry Format

| Field         | Type  | Description                                    |
|---------------|-------|------------------------------------------------|
| String Length | BYTE  | Length of string including null terminator    |
| String Data   | CHAR[]| Null-terminated ASCII string                   |
| Flags         | DWORD | Name flags (purpose varies)                    |

### Usage

Names are referenced by their zero-based index in the table. The name table is referenced by both the import and export tables for identifying classes, objects, and properties.

## Import Table

The import table defines external objects (classes, packages) that are referenced by objects in this package but defined elsewhere.

### Import Entry Format

| Field             | Type  | Description                                           |
|-------------------|-------|-------------------------------------------------------|
| Class Package     | INDEX | Name table index for the package containing the class |
| Class Name        | INDEX | Name table index for the class type                   |
| Package           | DWORD | ObjectReference to the package (often 0)              |
| Object Name       | INDEX | Name table index for the actual object name           |

*INDEX = CompactIndex*

### Class Resolution

For objects in the export table with negative class references, the import table provides the actual class type. The **Object Name** field typically contains the class name (e.g., "ComputerPersonal", "Texture", "Sound").

## Export Table

The export table defines all object instances contained within this package. Each entry describes an object's type, instance name (e.g., "ComputerPersonal3"), and location in the package.

### Export Entry Format

| Field         | Type  | Description                                              |
|---------------|-------|----------------------------------------------------------|
| Class         | INDEX | ObjectReference to class                                 |
| Super         | INDEX | ObjectReference to parent class                          |
| Group         | DWORD | Package group identifier                                 |
| Object Name   | INDEX | Name table index for instance name                       |
| Object Flags  | DWORD | Object-specific flags                                    |
| Serial Size   | INDEX | Size of serialized object data in bytes                  |
| Serial Offset | INDEX | Absolute offset to object data (only if Serial Size > 0) |

*INDEX = CompactIndex*

### Relationship Between Tables

1. Export entry's **Class** field (if negative) → Import table entry
2. Import table's **Object Name** → Name table (provides class type string)
3. Export entry's **Object Name** → Name table (provides instance name string)

**Example:**
```
Export[5].Class = -12  →  Import[11].ObjectName = 153  →  Names[153] = "ComputerPersonal"
Export[5].ObjectName = 847  →  Names[847] = "ComputerPersonal3"
```

This tells us Export[5] is an instance named "ComputerPersonal3" of class type "ComputerPersonal".

## Object Instance Data

Object instance data is located at the **Serial Offset** specified in the export table entry and extends for **Serial Size** bytes.

### Object Header Format

**Note:** Some object types (such as ConSpeech conversation objects) may not have a header and instead begin directly with their property list. Actor objects and other complex types typically include a header structure (approximately 15-17 bytes):

| Field              | Type  | Description                                    |
|--------------------|-------|------------------------------------------------|
| Class Reference 1  | INDEX | Class reference (same as export table)         |
| Class Reference 2  | INDEX | Class reference repeated (???)                 |
| Unknown Flags      | 13 bytes | Purpose unclear, likely object state flags  |

After this header (if present), the property list begins.

## Property Format

Object properties are serialized as a sequence of tagged values. Each property consists of:

### Property Entry Structure

| Field          | Type  | Description                                          |
|----------------|-------|------------------------------------------------------|
| Property Name  | INDEX | Name table index identifying the property            |
| Property Flags | BYTE  | Flags controlling property structure                 |
| Property Data  | varies| Property-specific data                               |

### Property Flags (1 byte)

The property flags byte encodes type information and size encoding:

| Bits  | Purpose          | Description                                    |
|-------|------------------|------------------------------------------------|
| 0-3   | Type Enum        | Property type (see Property Types table)       |
| 4-6   | Size Info        | Encodes property size (see Size Encoding table) |
| 7     | Array Index Flag | If set (0x80), array index byte follows        |

Note: Don't assume certain property data types will all use the same flags. The Unreal 1 engine has a habit of mixing flags to optimize space.

#### Size Encoding (bits 4-6, value 0-7)

The 3-bit size info field determines how the property size is specified:

| Value | Size Behavior                     | Bytes Read |
|-------|-----------------------------------|------------|
| 0     | Fixed size: 1 byte                | 0          |
| 1     | Fixed size: 2 bytes               | 0          |
| 2     | Fixed size: 4 bytes               | 0          |
| 3     | Fixed size: 12 bytes              | 0          |
| 4     | Fixed size: 16 bytes              | 0          |
| 5     | Variable size: read 1 byte size   | 1          |
| 6     | Variable size: read 2 bytes size  | 2          |
| 7     | Variable size: read 4 bytes size  | 4          |

**Space Optimization:** Common property sizes (1, 2, 4 bytes) are encoded directly in the flags byte, saving space. Variable-length or larger properties require an explicit size field.

### Property Types

The lower 4 bits of the flags byte indicate the property type:

| Value | Name       | Description                           |
|-------|------------|---------------------------------------|
| 0x00  | None       | Property list terminator              |
| 0x01  | Byte       | 8-bit unsigned integer or enum        |
| 0x02  | Int        | 32-bit signed integer                 |
| 0x03  | Bool       | Boolean value (1 byte)                |
| 0x04  | Float      | 32-bit floating point                 |
| 0x05  | Object     | Object reference (CompactIndex)       |
| 0x06  | Name       | Name table reference (CompactIndex)   |
| 0x07  | String     | Legacy string type                    |
| 0x08  | Class      | Class reference (CompactIndex)        |
| 0x09  | Array      | Array of values                       |
| 0x0A  | Struct     | Structure/compound data               |
| 0x0B  | Vector     | 3D vector (usually as struct)         |
| 0x0C  | Rotator    | Rotation (usually as struct)          |
| 0x0D  | Str        | String type (used in Deus Ex)         |
| 0x0E  | Map        | Map/dictionary (not commonly used)    |
| 0x0F  | FixedArray | Fixed-size array (not commonly used)  |

### Common Property Patterns

#### String Property (Type 0x0D)
```
[Property Name INDEX]
[Flags byte]  // Type 0x0D, size info in bits 4-6, array flag in bit 7
[Property Size]  // Only if size info = 5, 6, or 7 (1, 2, or 4 bytes)
[String Length INDEX]  // CompactIndex encoding
[String Data with null terminator]
```

**String Examples:**
```
// Short string with 1-byte size field
0x5D → Type=String, Size info=5 (read 1 byte)
[1 byte size][CompactIndex length][string data]

// Long string with 2-byte size field  
0x6D → Type=String, Size info=6 (read 2 bytes)
[2 byte size][CompactIndex length][string data]

// Fixed 12-byte string (no size field)
0x3D → Type=String, Size info=3 (fixed 12 bytes)
[CompactIndex length][string data]
```

**Important:** String length is encoded as a CompactIndex, not a simple byte. This allows strings to be longer than 255 characters. Values 0-63 appear as single bytes, while longer strings use multiple bytes.

#### Struct Property
```
[Property Name INDEX]
[Flags: 0x1A]  // Struct type (0x0A) + property size flag (0x10)
[Struct Type INDEX]  // References name table for struct type
[Struct Size BYTE]
[Struct Data...]
```

#### Array Element
```
[Property Name INDEX]
[Flags: 0x9A]  // Struct type (0x0A) + property size (0x10) + array index (0x80)
[Struct Type INDEX]
[Struct Size BYTE]
[Array Index BYTE]  // Position in array (0 = first, 1 = second, etc.)
[Struct Data...]
```

**Important Note:** The array index byte is **only present for elements after the first** (index >= 1). The first array element (index 0) does not include an array index byte even if it's part of an array.

### Property List Termination

The property list ends when a property name resolves to "None" (case-insensitive) in the name table, or when the serial size boundary is reached.

## Example: Decoding a Computer Object

Given an export entry for a ComputerPersonal object:

1. **Find the class**: Export.Class = -5 → Import[4].ObjectName = 89 → Names[89] = "ComputerPersonal"
2. **Find instance name**: Export.ObjectName = 234 → Names[234] = "ComputerPersonal8"
3. **Locate object data**: Jump to Export.SerialOffset
4. **Parse header** (if present): Skip CompactIndex + CompactIndex + 13 bytes, or start directly with properties
5. **Parse properties**:
   - Read property name INDEX → look up in Names table
   - Read flags byte → determine structure
   - Read property data based on flags
   - Repeat until "None" property or end of Serial Size

### Example Property: Speech String in ConSpeech

```
Offset  Data                Description
------  ------------------  -----------
0x00    [INDEX: 203]        Property name = "Speech"
0x01    0x1D               Flags: string type (0x0D) + property size (0x10)
0x02    0xBE               Property size = 190 bytes
0x03    0x7E 0x02          String length = 190 (CompactIndex)
0x05    "The dialog..."    String data (190 bytes including null)
```

### Example Property: userList Array of sUserInfo Structs

```
Offset  Data                Description
------  ------------------  -----------
0x00    [INDEX: 203]        Property name = "userList"
0x01    0x1A               Flags: struct type (0x0A) + property size (0x10)
0x02    [INDEX: 205]        Struct type = "sUserInfo"
0x03    0x18               Struct size = 24 bytes
0x04    0x07               Username string length (CompactIndex, fits in 1 byte)
0x05    "admin\0"          Username (7 bytes)
0x0C    0x09               Password string length (CompactIndex, fits in 1 byte)
0x0D    "password\0"       Password (9 bytes)
0x16    [4 bytes]          Integer (e.g., balance for ATM)
---     Second element (if exists)
0x1A    [INDEX: 203]        Property name = "userList" (same)
0x1B    0x9A               Flags: struct (0x0A) + size (0x10) + array (0x80)
0x1C    [INDEX: 205]        Struct type = "sUserInfo"
0x1D    0x18               Struct size = 24 bytes
0x1E    0x01               Array index = 1 (second element)
0x1F    ...                Second struct data
```

## Tips for Implementation

1. **Use CompactIndex decoding** for all INDEX fields AND for string lengths
2. **Handle negative ObjectReferences** by looking up imports
3. **Check property flags carefully** - property size flag behavior depends on bit 5
4. **The first array element has no array index byte**, but subsequent elements do
5. **Property parsing is challenging** - consider brute-force searching for known property names if full parsing proves difficult
6. **Different object classes have different property structures** - properties are class-specific
7. **Some objects skip the header** - ConSpeech and similar objects may start directly with properties
8. **String lengths use CompactIndex** - values 0-63 look like single bytes, but larger strings need proper CompactIndex decoding
