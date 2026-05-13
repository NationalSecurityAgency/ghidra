# Ghidra Serialization Filter

## Overview
As of version 12.0.5, Ghidra employs serialization input filters to address concerns about potential 
serialization vulnerabilities in relation to the use of Java RMI (e.g., Ghidra Server).  Filters 
are employed by both Ghidra Server and client applications.  The consequqnce of this filtering is
that all Java Object deserialization is subject to the filter even when it corresponds to purely 
local functionality.  This can occur with certain code that relies on serialization to facilitate 
object cloning (e.g., `org.apache.commons.collections4.functors.PrototypeFactory`).  When such cases occur
it may be neccessary to add allowed classes to a client-side serial input filter.

The Ghidra application discovers serial input filter specifications (`*.serial.filter`) files within
each Ghidra module's data directory (e.g., `Ghidra/Framework/FileSystem/data`) at startup.  The 
combined filter set is used to establish a global input serialization filter for Ghidra.

When adding functionality to Ghidra it may be neccessary to adjust the defined serial filter 
specifications.  When the filter rejects a class deserialization an `InvalidClassException` will be 
thrown and the rejected class name will be logged.  The log will need to be consulted since the 
exception itself does not convey the name of the offending class.

## Reference Information
- [Java Serialization Filtering](https://docs.oracle.com/javase/8/docs/technotes/guides/serialization/filters/serialization-filtering.html)

## Serial Input Filter Format
By default, the filter implementation will allow all primitive types (e.g., `int`, `char`, etc.) 
and primitive arrays.  Filter files need to specify all other Java classes that should allow
deserialization.  It is important to remember that all filter specifications will be combined into
a single global filter.

**IMPORTANT:** Although supported by Java's serial input filter specification, Ghidra does not
support the class rejection pattern starting with the `!` prefix.  This restriction stems from
Ghidra combining all serial filters into a single unordered filter specification.

The serial input filters (`*.serial.filter`) support the following entry types where each entry
must end with a semicolon `;`.  End of line comments may be specified with a leading `#` character.

- Allowed class name.  A class is specified by its full classname including package path:

```
    java.lang.String;
```
- Allowed inner class, anonymous class, or compiler‑generated synthetic class:

```
    ghidra.myplugin.Foo$MyInnerClass;
    
```
- Allowed class array (single dimension). Uses a `[L` prefix before the full classname.
NOTE: Anytime an array is allowed the base class must also be allowed. 

```
    [Ljava.lang.String;
````
- Allowed class array (two dimension). Uses a `[[L` prefix before the full classname.
NOTE: Anytime an array is allowed the base class must also be allowed.

```
    [[Ljava.lang.Integer;
````
- Wildcard class name specification can be used very carefully.  The `*` wildcard only spans a single 
package, while the `**` wildcard will include all subpackages.  Do not allow "Gadget classes" that 
can be exploited.

```
    ghidra.myplugin.*;
    [Lghidra.myplugin.*;
    ghidra.my*;
    [Lghidra.my*;
```
- Allowed remote interface that employ a dynamic Proxy classes (e.g., Java RMI Remote interface).

```
    remoteIf=ghidra.remote.MyRemoteIf;
```
- Maximum number of array elements (default: `32000`).  The maximum specified by any filter will be 
used.  A specified value will be ignore if less than the default.

```
    maxarray=200000;
```
- Maximum number of bytes in a serialization stream (default: `33554432` / 32MB).  The maximum 
specified by any filter will be used.  A specified value will be ignore if less than the default.

```
    maxbytes=100000000;
```
- Maximum references in a graph between objects (default: `10000`).  The maximum specified by any 
filter will be used.  A specified value will be ignore if less than the default.

```
    maxrefs=15000;
```
- Maximum depth of an object graph. (default: `50`).  The maximum specified by any filter will be used.  
A specified value will be ignore if less than the default.

```
    maxdepth=75;
```
**NOTE:** Default values shown above may be adjusted in the future.  Please report any filter failures
associated with standard Ghidra features.