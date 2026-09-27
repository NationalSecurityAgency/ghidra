# SwiftDemangler

This module provides support for demangling mangled [Swift](https://www.swift.org) symbols. Supported
mangled symbols begin with `$S`, `$s`, `_$S"`, `_$s`, or `_T`.

The demangler currently relies on making direct calls to the native Swift demangler tool, which
comes [bundled with Swift](https://www.swift.org/download/). For example:

```bash
% swift demangle --compact --expand _\$s7SwiftUI4ViewMp
Demangling for _$s7SwiftUI4ViewMp
kind=Global
  kind=ProtocolDescriptor
    kind=Type
      kind=Protocol
        kind=Module, text="SwiftUI"
        kind=Identifier, text="View"
protocol descriptor for SwiftUI.View
```

The resulting tree is parsed by the Ghidra Swift Demangler to form and apply a demangled symbol 
name.

The `Demangler Swift` Analyzer looks for the path to the native Swift Demangler binary 
in the `GHIDRA_SWIFT_DEMANGLER` environment variable. If that environment variable is not set, the
following paths will be tried on non-Windows platforms:
* `/usr/bin/swift-demangle`
* `/usr/bin/swift`
