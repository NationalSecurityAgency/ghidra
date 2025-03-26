# Ghidra 11.3.1 Change History (February 2025)

### Improvements
* _Multi-User_. Allow a repository without an Admin in the ACL to instantiate during server startup.  The `svrAdmin -grant` command line tool may be used to assign a new Admin to a repository.  Currently, when a user is removed from the server they are removed from all repository ACLs which could leave a repository without an Admin which will fail on server startup. (GP-5368)

### Bugs
* _Basic Infrastructure_. Fixed a bug that prevented Ghidra from remembering the last-used JDK when the `JAVA_HOME` environment variable was set. (GP-5381, Issue #7503)
* _Debugger:LLDB_. Fixed an issue with local-lldb.bat. (GP-5347, Issue #4977)
* _Importer:ELF_. Packed relocations in MIPS 64-bit binaries are now applied correctly.  Previously, packed relocations would reference address `0x0`. (GP-5365)
* _Importer:ELF_. Corrected ELF Import bug which failed to pin absolute symbols and reported an Object Deleted error. (GP-5374)
* _Multi-User_. Corrected regression bug which would prevent Ghidra Server users from specifying a different login username. (GP-5362, Issue #7454)
* _Processors_. Added implementation for ARM `vld4` and `vst4` instructions. (GP-5268)
* _Scripting_. PyGhidra can now find modules that live in directories specified by the Bundle Manager. (GP-5298)
* _Scripting_. Fixed a PyGhidra issue that prevented accessing Java getters/setters as properties on non-public classes. (GP-5348, Issue #7450)
* _Scripting_. PyGhidra now respects the `application.settingsdir` property set in Ghidra's `launch.properties`. (GP-5372, Issue #7481)
* _SourceMatching_. Corrected implementation of DWARF source line `DW_LNS_const_add_pc` instruction. (GP-5353)

### Notable API Changes
* _Multi-User_. (GP-5362) Revised `PasswordDialog` constructors to simplify those used for password-only entry.

# Ghidra 11.3 Change History (February 2025)

### New Features
* _Analysis_. Added new logic to export facts and source/sink logic to Datalog. (GP-3443)
* _Data Types_. Added string translation option to use LibreTranslate to translate strings found in a binary. NOTE: This plugin is not enabled by default; the user needs to configure tool to include it if they want to use it. (GP-4877)
* _Debugger_. Added TraceRMI connector for JDI (Java/Dalvik targets). (GP-4760)
* _Debugger_. TraceRMI now supports debugging Java/Dalvik on Android. (GP-4893)
* _Debugger:Agents_. The deprecated Debugger plugins and connectors (e.g., IN-VM) have been removed. (GP-1978)
* _Debugger:LLDB_. Added support for debugging macOS kernels with lldb. (GP-5209)
* _Debugger:Targets_. Added support for local and eXDI-mode kernel debugging (dbgeng/dbgmodel). (GP-5185)
* _Emulator_. Added a high-performance p-code emulator using Just-in-Time translation to bytecode. (GP-4643)
* _Graphing_. Added two new __Flow Chart__ layouts for the function graph. These layouts organize code blocks into a tree structure and use orthogonal edge routing. One centers the parent block over the children and the other keeps the parent left aligned with its left most child. (GP-4988, Issue #1406)
* _GUI_. Updated the File chooser to allow users to edit the path field. (GP-3492, Issue #5291, #7150)
* _Importer_. Added a `Load Libraries` action that allows the user to load libraries after a program has already been imported. (GP-4919, Issue #396)
* _Scripting_. Integrated the DoD Cyber Crime Center's Pyhidra tool (renamed to PyGhidra) to provide a native CPython 3 interface to Ghidra. (GP-4816, Issue #6900)
* _Scripting_. Added a new button to the Script Manager that allows the user to edit scripts in Visual Studio Code.  Additionally, added a new action to the CodeBrowser under __Tools -> Create VSCode Module Project...__ that replaces the old `VSCodeProjectScript.java` script. (GP-5148)
* _Search_. Added an action to allow users to search Decompiled text from __Search -> Decompiled Text...__. (GP-4839, Issue #6795)
* _SourceMatching_. Added manager for source code and line number information to the Ghidra database. (GP-3883)
* _SourceMatching_. Added `SourceFilesTablePlugin` for viewing source file information and managing local paths. (GP-4190)

### Improvements
* _Analysis_. Corrected a vftable naming issue in RTTI Analyzer where programs with PDB information were not naming vftables with associated class name correctly. (GP-4687)
* _BSim_. Added a `status` command to `bsim_ctl`. (GP-5129, Issue #7102)
* _BSim_. Added ability to specify user login info with postgres/elastic BSim URLs for the `bsim` command line tool and API.  Updated BSim Server Manager GUI to allow user login name to be specified for postgres/elastic BSim server entries. (GP-5167)
* _BSim_. Updated BSim bundled postgresql server to 15.10 to resolve incompatibility with `openssl 3.2.2`. (GP-5212, Issue #6115, #7084)
* _BSim_. Tweaked BSim Dark Mode colors. (GP-5223, Issue #7312)
* _Build_. Fixed a build issue with Gradle 8.12. (GP-5226)
* _CodeBrowser_. Users can now apply bookmarks in the Listing to interior data of structures applied to memory. (GP-4820)
* _Data Types_. The Decompiler now propagates and displays names for enumeration data-types that have been partially truncated. (GP-2470)
* _Debugger_. Improved the behavior for Android targets. (GP-5034, Issue #6386)
* _Debugger:Agents_. Removed __raw gdb__ connector. Instead, just leave the __Image__ option blank in the __gdb__ connector. (GP-4906)
* _Debugger:Agents_. Added __Architecture__ and __Endian__ options to several gdb launchers. (GP-5005)
* _Debugger:GDB_. Added distinct launchers for qemu-system (vs. qemu-user). Windows only supports qemu-system. (GP-5051, Issue #7095)
* _Debugger:GDB_. Added __Pull all section mappings__ to the __qemu + gdb__ debug launcher. (GP-5089, Issue #7118)
* _Debugger:Listing_. __Load Emulator from Programs__ has been removed from the __Auto-Read Memory__ menus. It is now the default behavior for pure emulation, unless __Do Not Read Memory__ is selected. (GP-5134)
* _Decompiler_. Updated the Decompiler function name colors to match the Listing. (GP-5085, Issue #7053)
* _Decompiler_. Improved the Decompiler's handling of signed integer comparisons in the presence of the AARCH64 `ccmp` instruction. (GP-5158)
* _Demangler_. Added ability to process Microsoft C-style mangled function symbols. (GP-4898, Issue #1514)
* _Demangler_. Improved processing of anonymous namespaces in vxtables. (GP-5101)
* _Demangler_. The builtin `int` type in Swift binaries has been changed from 8 bytes to 4 bytes.  The Swift Demangler now demangles the `Swift.Int` type to `__int64` (or `__int32` on 32-bit programs) to avoid conflicts with non-Swift structures and functions that may be found in the program. (GP-5182, Issue #6784)
* _Eclipse Integration_. GhidraDev 5.0.0 has been released which supports creating and launching new Ghidra module and scripting projects with PyGhidra support (using the PyDev Eclipse plugin). (GP-5138)
* _FileSystems_. Updated to dex2jar-2.4.24 and asm-9.7.1 libraries. (GP-5220)
* _Function_. Now prevent function auto-storage assignment for DEFAULT (`undefined`) datatype.  Changed Demangler to produce undefined-typedef in place of a DWORD-typedef when producing a default-named datatype.  Demangler will still create an empty named Structure in many cases.  Decompiler will no longer assign the `undefined` datatype to variables. (GP-4886)
* _Graphing_. Added an action to toggle between the Listing and Function Graph views (`Ctrl-Space`). (GP-4947)
* _Graphing_. Added options for which corner the Function Graph Satellite view is docked within the main Graph window. (GP-4996)
* _GUI_. Updated theming to allow users to change the table's base font and monospaced fonts separately. (GP-4873, Issue #6853)
* _GUI_. Changed the Linux default theme from `Nimbus` to `Flat Light`. (GP-4973)
* _GUI_. Updated Key Binding assignment to allow users to choose `Backspace` and `Enter`. (GP-5007, Issue #6972)
* _GUI_. Upgraded FlatLaf to 3.5.4. (GP-5027)
* _GUI_. Added options to the __Clear With Options...__ action to allow just clearing instructions or data instead of having to do both or neither. (GP-5084, Issue #7082)
* _GUI_. Users can now pick a language by double-clicking in the Importer Dialog. (GP-5097, Issue #7135)
* _GUI_. Updated the `Flat Dark` table inactive selection color. (GP-5108, Issue #7134)
* _GUI_. Users can now press the `Escape` key to close windows that contain only a single component provider. (GP-5114, Issue #7136)
* _GUI_. Updated table and tree filters to support `Ctrl-F` to place focus on the cursor.  Also added an action to hide and show the filter. (GP-5115, Issue #7136)
* _GUI_. The Function Call Tree plugin now distinguishes between call references and non-call references. (GP-5116)
* _GUI_. Changed actions that _show_ a component provider into toggle actions that _hide_ the provider if already visible. (GP-5117, Issue #7136)
* _GUI_. Added a `Downloads` folder to the File Chooser. (GP-5118, Issue #7121)
* _GUI_. Added the Unresolved Reference color to the Theme Configuration. (GP-5157)
* _GUI_. Added support for expressions in address input fields. (GP-5196, Issue #7227)
* _Importer_. Fixed a performance issue when loading libraries on Windows. (GP-5208)
* _Importer:COFF_. The MS Common Object File Format (COFF) loader now recognizes AARCH64 binaries. (GP-5153)
* _Importer:COFF_. Added relocation handlers for ARM and AARCH64 COFF files. (GP-5154)
* _Importer:ELF_. The ElfLoader imagebase option can now contain a leading `0x`. (GP-4955, Issue #6912)
* _Languages_. Added support for golang 1.23. (GP-4870)
* _Listing_. Added ability to copy data values and referenced data values to the clipboard via the copy special action. (GP-5036)
* _Listing_. Hovering on addresses in the Listing now show offsets in both decimal and hexadecimal. (GP-5176, Issue #7239)
* _Navigation_. Improved GoTo Dialog to support full namespace paths with wildcards. (GP-4930)
* _PDB_. Improved PDB composite reconstruction when padding components are required to facilitate proper packing. (GP-5037, Issue #1030)
* _PDB_. Enabled the processing of some older PDB component versions by fixing up previously written code intended for processing them. (GP-5072, Issue #7100)
* _PDB_. Improved searching for PDB files. (GP-5174, Issue #7200)
* _Processors_. Made a number of improvements to the TI_MSP430 compiler spec. (GP-4202)
* _Scripting_. `GhidraScript.askFile()` no longer throws an `IllegalArgumentException` in headless mode when passing in a valid path argument to a file that does not yet exist. (GP-5010, Issue #7025)
* _Scripting_. Upgraded Jython to 2.7.4. (GP-5210)
* _Search_. Added a button to the Instruction Pattern Search dialog that allows users to add more instructions to the current set of patterns. (GP-2418)
* _SourceMatching_. Added source file mapping for golang. (GP-4196)
* _SourceMatching_. Added `OpenSourceFileAtLineInVSCodeScript.java` and `OpenSourceFileAtLineInEclipseScript.java` for communicating source map information to vscode and eclipse. (GP-5217)
* _Terminal_. Added keys to adjust font size. Fixed theme changes should take immediate effect. (GP-5003)

### Bugs
* _Analysis_. Fixed issue in RTTIAnalyzer introduced with previous fix to incorrect anonymous PDB namespaces. Leaving the old name as a secondary label caused RTTI Script to assume two different classes with same Listing contents. (GP-5146, Issue #3213)
* _Analysis_. Fixed issue where a TEB Analyzer failure reverts entire analysis. (GP-5338)
* _Assembler_. Improved `WildcardAssembler` to have less stringent requirements for input `contextreg` values. (GP-5288, Issue #7195)
* _BSim_. Corrected various bugs related to BSim elasticsearch use. (GP-1830)
* _BSim_. Corrected various bugs affecting BSim Elasticsearch use. (GP-5207)
* _BSim_. Corrected BSim apply signature when source calling convention is unknown (e.g., custom) to destination. (GP-5216, Issue #7310)
* _BSim_. Corrected `NullPointerException` in `BSimFeatureVisualizer`. (GP-5252, Issue #7311)
* _Byte Viewer_. Fixed bug that cleared the Byte Viewer __Address__ column when changing fonts. (GP-4998)
* _CParser_. Parsing header files with the CParser will now stop parsing when a `#error` directive is encountered.  Numerous parsing errors involving comment parsing have been fixed. (GP-5025, Issue #7001)
* _CParser_. Added CParser support for `__vectorcall`, `__rustcall`, and `__pascal` calling conventions. (GP-5150)
* _Debugger_. Fixed issue toggling and deleting breakpoints and watchpoints in lldb. (GP-5271)
* _Debugger:dbgeng.dll_. Provided fix for missing stack values for some variants of `dbgmodel.dll`. (GP-5195)
* _Debugger:GDB_. Added a __Refresh__ action for stack frames other than just the topmost one. (GP-5169)
* _Debugger:GDB_. Fixed endianness of register value display in Model tree. (GP-5230)
* _Debugger:Listing_. Fixed issue with obtrusive and spurious auto-seek events. (GP-5266)
* _Debugger:Mappings_. Fixed issue with registers not displaying because of a conflict in language/compiler opinion between the back and front ends, particularly affecting gdb with Windows x64 targets. (GP-5232)
* _Debugger:Memory_. Fixed an issue with manually adding a Region from the UI. (GP-5164, Issue #7176)
* _Debugger:Memory_. Fixed Auto-Read memory when using Force Full View. (GP-5180, Issue #7176)
* _Debugger:Modules_. Fixed `NullPointerException` from `TraceModule.getBase().getAddressSpace()` commonly seen when launching and mapping Windows targets. (GP-5102, Issue #7153)
* _Debugger:Objects_. Fixed issue where __Model__ tree pane didn't update after editing a register in the CLI. (GP-5229)
* _Debugger:Registers_. Fixed issue where registers could not be edited. (GP-5213)
* _Debugger:Trace_. Fixed unflushed object stream in `Saveable TracePropertyMap`. (GP-5121)
* _Decompiler_. Fixed occurrence of _"Unable to create datatype associated with symbol"_ exceptions when using the __Override Signature__ action. (GP-5006, Issue #3694)
* _Decompiler_. Fixed a bug where the Decompiler failed to resolve references into structures that were recursively defined. (GP-5038)
* _Decompiler_. Fixed a Decompiler bug encountered when renaming a token that caused middle-mouse highlights to persists. (GP-5040, Issue #7077)
* _Decompiler_. Fixed possible infinite loop when inlining recursive functions in the Decompiler. (GP-5073, Issue #5824)
* _Decompiler_. Fixed crash in the Decompiler triggered while recovering a heap string written at a negative offset relative to the pointer. (GP-5130)
* _Decompiler_. Fixed infinite loop in the Decompiler triggered by data-types with a nested structure containing an array. (GP-5184, Issue #7212)
* _Diff_. Fixed missing parameters in the Diff Tool Listing view. (GP-5155)
* _Eclipse Integration_. Fixed an issue with the GhidraDev Eclipse plugin's __Import Ghidra Module Source__ feature that prevented the module's extension points from being discovered by Ghidra when launched with the project's run/debug configuration. (GP-5125, Issue #7047)
* _Framework_. Fixed an exception that occurred when closing the Front End tool. (GP-4962, Issue #6937)
* _Function_. Corrected Function custom storage editor's handling of compound storage checking for big-endian programs. (GP-5198)
* _Function Compare_. Fixed bug in LocalBsimQueryScript where showing new function comparison windows would stop working after you closed the comparison window the first time. (GP-5329)
* _GUI_. Corrected Function custom storage editor datatype selection which failed to properly clone datatype to program's data organization. (GP-4913)
* _GUI_. Updated the Ghidra Script table so all columns are resizable. (GP-4983, Issue #6918)
* _GUI_. Fixed table selection bug in the Memory Map provider when a table filter is applied. (GP-4984)
* _GUI_. Fixed fast scrolling behavior sometimes seen when using the `Flat Light` or `Dark` themes. (GP-4993, Issue #6952)
* _GUI_. Fixed entropy legend labels to be visible in all themes. (GP-5103)
* _GUI_. Fixed a bug that caused the table Column Filter Dialog to not update when new columns were added. (GP-5289, Issue #7175)
* _GUI_. Fixed the Escape key sometimes not working in Tree and Table cell editors. (GP-5313, Issue #7241)
* _Importer:PE_. Provided a fix related to an incorrect length for Windows PE `IMAGE_DEBUG_MISC` processing. (GP-5199, Issue #7285)
* _Importer:PE_. Fixed a `NullPointerException` that could occur when processing debug COFF symbol information. (GP-5321, Issue #7411)
* _Multi-User_. Corrected Ghidra versioning bug where server may not be updated with latest checkout details following a checkout update.  This could allow file versions to be deleted from the repository when they still have corresponding checkout(s).  To correct existing checkout data, all project files should be checked-in, without keeping checked-out, then re-checkout if necessary to correct the repository metadata. (GP-5123)
* _Multi-User_. Corrected Ghidra Server concurrent modification error which could occur during client repository disposal.   Improved control of java path used by `ghidraSvr` script and other Ghidra launch scripts through the use of `JAVA_HOME` environment variable. (GP-5161)
* _Processors_. Added EVEX writemask to pcode for x86 AVX-512 instructions. (GP-4660)
* _Processors_. Corrected ARM VFPv2 instructions which were not disassembling correctly. (GP-5181, Issue #7259)
* _ProgramDB_. Corrected issue related to locally stored Program user data that may not handle language version upgrades properly. (GP-5205)
* _ProgramTree_. Fixed `NullPointerException` when restoring a program tree window in which a tab was previously closed. (GP-5279)

### Notable API Changes
* _Debugger:Agents_. (GP-1978) The entirety of `DebuggerObjectModel` and most of its related paraphernalia have been removed. Other parts have been refactored into other components. `DebuggerObjectModel` / `TraceRecorder` is replaced by `TraceRmi` / `Target`. `TargetObject` is replaced by `TraceObject`. Some `TargetObject` interfaces, e.g., `TargetDeletable`, do not have replacement `TraceObject` interfaces. Instead, they are implied by applicable `RemoteMethods`. Others, e.g., `TargetAccessConditioned`, are removed without replacement.  `DataType`- and `Symbol`-related objects are removed. They have not been used. If needed later, the intent is to provide rmi-based access to the trace's symbol table and data type manager. `TargetObjectSchema` is replaced by `TraceObjectSchema`. `TraceObjectKeyPath` is renamed `KeyPath`. `PathUtils` and many uses of `List<String>` have been replaced by `KeyPath`. `AnnotatedSchemaContext` and related are removed. `SshPtyFactory` and related are removed.
* _Emulator_. (GP-4643) Added `JitPcodeEmulator` and many, many related classes. `PcodeArithmetic`: changed `modBeforeStore` and `modAfterLoad` to include `AddressSpace` and `PcodeOp` parameters.  `SleighInstructionDecoder.decodeInstruction` now returns a `PseudoInstruction`. PcodeExecutor: added `getIntConst`, `getLoadStoreSpace`, `getLoadStoreOffset`, `getStoreValue`, `getBranchTarget`, `getConditionalBranchPredicate`, `getIndirectBranchTarget`, `getUseropName`, `getCallotherOpNumber`.
* _BSim_. (GP-5167) Changed BSim API to convey non-default username via the `BSimServerInfo` class or the `userinfo` field of postgres/elastic BSim URLs.  The user argument has been dropped to the `FunctionDatabase.changePassword` method which will always change the password for the connected user.   Renamed `FunctionDatabase.Error` class to `FunctionDatabase.BSimError` to avoid naming conflict with `java.lang.Error`.
* _Data Types_. (GP-3625) Added `FileDataTypeManager` static methods for creating a Data Type Archive with a specific processor and compiler specification.  Improved `CParserUtils` parse methods to separate the cases where parsing into an existing Data Type Manager versus parsing into a new Data Type Archive where a processor and compiler specification may specified.
* _Debugger:Listing_. (GP-5134) `DebuggerListingProvider#setAutoReadMemorySpec` and related no longer accept `LoadEmulatorAutoReadMemorySpec`. Added `AutoReadMemorySpec#getEffective`.
* _Decompiler_. (GP-5085) Updated `DecompileOptions` to remove the `getFunctionColor()` method. There is no replacement for this method as the function color is now being set in the Listing Settings menu and is coordinated across the Listing and Decompile panes.
* _Demangler_. (GP-4898) Within the `Demangler` interface, Ghidra 9.2-deprecated methods were removed, Ghidra 11.3-deprecations were set on other methods, and  new methods were created.  The new methods and much of the Demangler fabric now makes use of a `MangledContext` in place of a `String`.  This allows greater flexibility in controlling how symbols get demangled.  These changes have been reflected in abstract and non-abstract methods in `AbstractDemanglerAnalzyer`.  Users of deprecated methods within `Demangler` and `DemanglerUtil` should migrate to newer methods (see javadoc).
* _GUI_. (GP-5007) Added a new widget, the `docking.KeyEntryPanel`, as a drop-in replacement for clients using the `docking.KeyEntryTextField`.  This is not a required change.
* _GUI_. (GP-5196) The static method `evaluateToLong(String s)` in `AddressEvaluator` has been moved to a new class called `ExpressionEvaluator`. Also, the `AddressInput` field component has been changed to accept Programs instead of just an AddressFactory (which is still supported) so that any dialog using an `AddressInput` component can now accept symbol names, memory block names, and mathematical expressions.
* _Importer_. (GP-5208) GFileSystems now need to implement `lookup(path, comparator)`.   Classes that fail to provide an implementation will fall back to using `lookup(path)`, and an error will be logged.
* _Search_. (GP-4911) The API script method `findBytes()` no longer supports finding matches that span gaps in the memory blocks. The internal classes for performing memory searches were completely re-written in Ghidra release 11.2. In release 11.3, the old classes were removed and uses of them in the `findBytes()` method were replaced with the new memory search code. The new search API currently does not support matches that span non-contiguous memory and it isn't clear if that is actually useful; so for now, that method was deprecated and no longer finds matches in gaps even if the boolean is true. In the unlikely event someone actually uses this, please contact the Ghidra team.
* _Assembler_. (GP-5288) Added `AssemblyResolvedPatterns.withContext`.  Added `ContextCommit.getWordIndex` and `getMask`.
* _BSim_. (GP-1830) Dropped use of `json-simple` library in favor of `gson`.
* _Debugger_. (GP-5271) Added `TraceBreakpoint.isAlive(long snap)`.  Deprecated `TraceBreakpoint.getLifespan()`.  Added `TraceObject.isAlive(long snap)`.
* _Debugger:Listing_. (GP-5266) Renamed `DebuggerCoordinates.equalsIgnoreRecorderAndView` to `equalsIgnoreTargetAndView`.  Added `DebuggerCoordinates.differsOnlyByPatch`.  Added `TraceSchedule.differsOnlyByPatch`.  Added `Sequence.differsOnlyByPatch`.
* _Debugger:Memory_. (GP-5164) Renamed `DebuggerAddRegionDialog#setName` to `setPath`.

