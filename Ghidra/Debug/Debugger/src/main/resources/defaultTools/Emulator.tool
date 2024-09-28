<?xml version="1.0" encoding="UTF-8"?>
<TOOL_CONFIG CONFIG_NAME="NO_LONGER_USED">
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.Program" />
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.DataTypeArchive" />
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.trace.model.Trace" />
    <ICON LOCATION="emulator32.png" />
    <TOOL TOOL_NAME="Emulator" INSTANCE_NAME="">
        <OPTIONS />
        <PACKAGE NAME="Debugger">
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.interpreters.DebuggerInterpreterPlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerPlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.tracermi.launcher.TraceRmiLauncherServicePlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.service.tracermi.TraceRmiPlugin" />
        </PACKAGE>
        <PACKAGE NAME="Ghidra Core">
            <EXCLUDE CLASS="ghidra.plugins.fsbrowser.FileSystemBrowserPlugin" />
            <INCLUDE CLASS="ghidra.app.plugin.core.interpreter.InterpreterPanelPlugin" />
        </PACKAGE>
        <ROOT_NODE X_POS="320" Y_POS="192" WIDTH="1920" HEIGHT="1017" EX_STATE="0">
            <SPLIT_NODE WIDTH="1906" HEIGHT="921" DIVIDER_LOCATION="767" ORIENTATION="VERTICAL">
                <SPLIT_NODE WIDTH="100" HEIGHT="100" DIVIDER_LOCATION="0" ORIENTATION="VERTICAL">
                    <SPLIT_NODE WIDTH="1906" HEIGHT="703" DIVIDER_LOCATION="251" ORIENTATION="HORIZONTAL">
                        <SPLIT_NODE WIDTH="477" HEIGHT="703" DIVIDER_LOCATION="433" ORIENTATION="VERTICAL">
                            <COMPONENT_NODE TOP_INFO="3">
                                <COMPONENT_INFO NAME="DataTypes Provider" OWNER="DataTypeManagerPlugin" TITLE="Data Type Manager" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629452" />
                                <COMPONENT_INFO NAME="Program Tree" OWNER="ProgramTreePlugin" TITLE="Program Trees" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004460958955487" />
                                <COMPONENT_INFO NAME="Symbol Tree" OWNER="SymbolTreePlugin" TITLE="Symbol Tree" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004460958955482" />
                                <COMPONENT_INFO NAME="Debug Console" OWNER="DebuggerConsolePlugin" TITLE="Debug Console" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629451" />
                            </COMPONENT_NODE>
                            <COMPONENT_NODE TOP_INFO="0">
                                <COMPONENT_INFO NAME="Model" OWNER="DebuggerModelPlugin" TITLE="Model" ACTIVE="true" GROUP="Debugger.Core" INSTANCE_ID="3622004957652629465" />
                            </COMPONENT_NODE>
                        </SPLIT_NODE>
                        <SPLIT_NODE WIDTH="1293" HEIGHT="590" DIVIDER_LOCATION="785" ORIENTATION="VERTICAL">
                            <SPLIT_NODE WIDTH="1386" HEIGHT="638" DIVIDER_LOCATION="705" ORIENTATION="VERTICAL">
                                <SPLIT_NODE WIDTH="1425" HEIGHT="703" DIVIDER_LOCATION="679" ORIENTATION="HORIZONTAL">
                                    <SPLIT_NODE WIDTH="965" HEIGHT="703" DIVIDER_LOCATION="506" ORIENTATION="VERTICAL">
                                        <COMPONENT_NODE TOP_INFO="0">
                                            <COMPONENT_INFO NAME="Listing" OWNER="DebuggerListingPlugin" TITLE="Dynamic" ACTIVE="true" GROUP="Core" INSTANCE_ID="3622004957275142089" />
                                        </COMPONENT_NODE>
                                        <COMPONENT_NODE TOP_INFO="0">
                                            <COMPONENT_INFO NAME="Listing" OWNER="CodeBrowserPlugin" TITLE="Listing: " ACTIVE="true" GROUP="Core" INSTANCE_ID="3622004957275142087" />
                                        </COMPONENT_NODE>
                                    </SPLIT_NODE>
                                    <COMPONENT_NODE TOP_INFO="0">
                                        <COMPONENT_INFO NAME="Decompiler" OWNER="DecompilePlugin" TITLE="Decompile" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957275142080" />
                                        <COMPONENT_INFO NAME="Bytes" OWNER="ByteViewerPlugin" TITLE="Bytes: No Program" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142082" />
                                        <COMPONENT_INFO NAME="Data Window" OWNER="DataWindowPlugin" TITLE="Defined Data" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629460" />
                                        <COMPONENT_INFO NAME="Defined Strings" OWNER="ViewStringsPlugin" TITLE="Defined Strings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629468" />
                                        <COMPONENT_INFO NAME="Equates Table" OWNER="EquateTablePlugin" TITLE="Equates Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142085" />
                                        <COMPONENT_INFO NAME="External Programs" OWNER="ReferencesPlugin" TITLE="External Programs" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142088" />
                                        <COMPONENT_INFO NAME="Functions Window" OWNER="FunctionWindowPlugin" TITLE="Functions" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142091" />
                                        <COMPONENT_INFO NAME="Relocation Table" OWNER="RelocationTablePlugin" TITLE="Relocation Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629467" />
                                        <COMPONENT_INFO NAME="Modules" OWNER="DebuggerModulesPlugin" TITLE="Modules" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629455" />
                                        <COMPONENT_INFO NAME="Registers" OWNER="DebuggerRegistersPlugin" TITLE="Registers" ACTIVE="true" GROUP="Debugger.Core" INSTANCE_ID="3622004957652629469" />
                                        <COMPONENT_INFO NAME="Breakpoints" OWNER="DebuggerBreakpointsPlugin" TITLE="Breakpoints" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629466" />
                                        <COMPONENT_INFO NAME="DebuggerInterpreterPlugin" OWNER="InterpreterPanelPlugin" TITLE="Interpreter" ACTIVE="false" GROUP="Default" INSTANCE_ID="3381048220378451114" />
                                        <COMPONENT_INFO NAME="Interpreter" OWNER="InterpreterPanelPlugin" TITLE="Interpreter" ACTIVE="false" GROUP="Default" INSTANCE_ID="3398988136451618475" />
                                    </COMPONENT_NODE>
                                </SPLIT_NODE>
                                <SPLIT_NODE WIDTH="1386" HEIGHT="189" DIVIDER_LOCATION="495" ORIENTATION="HORIZONTAL">
                                    <COMPONENT_NODE TOP_INFO="0">
                                        <COMPONENT_INFO NAME="Data Type Preview" OWNER="DataTypePreviewPlugin" TITLE="Data Type Preview" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629448" />
                                    </COMPONENT_NODE>
                                    <COMPONENT_NODE TOP_INFO="0">
                                        <COMPONENT_INFO NAME="Virtual Disassembler - Current Instruction" OWNER="DisassembledViewPlugin" TITLE="Disassembled View" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142084" />
                                    </COMPONENT_NODE>
                                </SPLIT_NODE>
                            </SPLIT_NODE>
                            <COMPONENT_NODE TOP_INFO="0">
                                <COMPONENT_INFO NAME="Bookmarks" OWNER="BookmarkPlugin" TITLE="Bookmarks" ACTIVE="false" GROUP="Core.Bookmarks" INSTANCE_ID="3622004460958955486" />
                            </COMPONENT_NODE>
                        </SPLIT_NODE>
                    </SPLIT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Function Call Trees" OWNER="CallTreePlugin" TITLE="Function Call Trees" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004460958955483" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
                <SPLIT_NODE WIDTH="1906" HEIGHT="214" DIVIDER_LOCATION="348" ORIENTATION="HORIZONTAL">
                    <COMPONENT_NODE TOP_INFO="1">
                        <COMPONENT_INFO NAME="Regions" OWNER="DebuggerRegionsPlugin" TITLE="Regions" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629463" />
                        <COMPONENT_INFO NAME="Stack" OWNER="DebuggerStackPlugin" TITLE="Stack" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629449" />
                        <COMPONENT_INFO NAME="Console" OWNER="ConsolePlugin" TITLE="Console" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957275142081" />
                        <COMPONENT_INFO NAME="Watches" OWNER="DebuggerWatchesPlugin" TITLE="Watches" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004460958955481" />
                    </COMPONENT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Threads" OWNER="DebuggerThreadsPlugin" TITLE="Threads" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629454" />
                        <COMPONENT_INFO NAME="Time" OWNER="DebuggerTimePlugin" TITLE="Time" ACTIVE="true" GROUP="Default" INSTANCE_ID="3622004957652629457" />
                        <COMPONENT_INFO NAME="Pcode Stepper" OWNER="DebuggerPcodeStepperPlugin" TITLE="Pcode Stepper" ACTIVE="false" GROUP="Default" INSTANCE_ID="3381240965691561509" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
            </SPLIT_NODE>
            <WINDOW_NODE X_POS="426" Y_POS="178" WIDTH="1033" HEIGHT="689">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Script Manager" OWNER="GhidraScriptMgrPlugin" TITLE="Script Manager" ACTIVE="false" GROUP="Script Group" INSTANCE_ID="3622004460958955484" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="423" Y_POS="144" WIDTH="927" HEIGHT="370">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memory Map" OWNER="MemoryMapPlugin" TITLE="Memory Map" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004460958955479" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="383" Y_POS="7" WIDTH="1020" HEIGHT="1038">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Graph" OWNER="FunctionGraphPlugin" TITLE="Function Graph" ACTIVE="false" GROUP="Function Graph" INSTANCE_ID="3622004957652629470" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="550" Y_POS="206" WIDTH="655" HEIGHT="509">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Register Manager" OWNER="RegisterPlugin" TITLE="Register Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142090" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="287" Y_POS="186" WIDTH="1424" HEIGHT="666">
                <SPLIT_NODE WIDTH="1408" HEIGHT="559" DIVIDER_LOCATION="573" ORIENTATION="HORIZONTAL">
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Symbol Table" OWNER="SymbolTablePlugin" TITLE="Symbol Table" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3622004957652629461" />
                    </COMPONENT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Symbol References" OWNER="SymbolTablePlugin" TITLE="Symbol References" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3622004957652629462" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Checksum Generator" OWNER="ComputeChecksumsPlugin" TITLE="Checksum Generator" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957275142086" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Tags" OWNER="FunctionTagPlugin" TITLE="Function Tags" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629453" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Comment Window" OWNER="CommentWindowPlugin" TITLE="Comments" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629459" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Python" OWNER="InterpreterPanelPlugin" TITLE="Python" ACTIVE="false" GROUP="Default" INSTANCE_ID="3527612550976678285" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Call Graph" OWNER="FunctionCallGraphPlugin" TITLE="Function Call Graph" ACTIVE="false" GROUP="Function Call Graph" INSTANCE_ID="3622004957652629450" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="658" Y_POS="1489" WIDTH="470" HEIGHT="540">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memory Range Mappings" OWNER="DebuggerStaticMappingPlugin" TITLE="Memory Range Mappings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3367472270453938012" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="BundleManager" OWNER="GhidraScriptMgrPlugin" TITLE="Bundle Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004460958955485" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="2105" Y_POS="966" WIDTH="1122" HEIGHT="546">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Objects" OWNER="DebuggerTimelinePlugin" TITLE="Objects" ACTIVE="false" GROUP="Default" INSTANCE_ID="3366353018521038486" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Static Mappings" OWNER="DebuggerStaticMappingPlugin" TITLE="Static Mappings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629464" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="1429" Y_POS="806" WIDTH="982" HEIGHT="580">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memview" OWNER="DebuggerMemviewPlugin" TITLE="Memview" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629458" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memory" OWNER="DebuggerMemoryBytesPlugin" TITLE="Memory" ACTIVE="false" GROUP="disconnected" INSTANCE_ID="3622004460958955478" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Jython" OWNER="InterpreterPanelPlugin" TITLE="Jython" ACTIVE="false" GROUP="Default" INSTANCE_ID="3622004957652629456" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
        </ROOT_NODE>
        <PREFERENCES>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointLocationTableModel:State:Name:Address:Trace:Threads:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.State" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="100" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="100" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Trace" WIDTH="100" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Threads" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Comment" WIDTH="100" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Sleigh" WIDTH="30" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.memview.MemviewMapModel:Name:Start Address:End Address:Start Time:End Time:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="90" VISIBLE="true" />
                        <COLUMN NAME="Start Address" WIDTH="90" VISIBLE="true" />
                        <COLUMN NAME="End Address" WIDTH="90" VISIBLE="true" />
                        <COLUMN NAME="Start Time" WIDTH="90" VISIBLE="true" />
                        <COLUMN NAME="End Time" WIDTH="90" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Name:Created:Destroyed:State:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Created" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Destroyed" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="State" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="151" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Module Name:Base Address:Lifespan:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Module Name" WIDTH="222" VISIBLE="true" />
                        <COLUMN NAME="Base Address" WIDTH="144" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="143" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerLegacyStackPanel$StackTableModel:Level:PC:Function:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Level" WIDTH="19" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.PC" WIDTH="215" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Function" WIDTH="215" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Comment" WIDTH="215" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerLegacySectionsPanel$SectionTableModel:Start Address:End Address:Section Name:Module Name:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Start Address" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.End Address" WIDTH="92" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Section Name" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Module Name" WIDTH="92" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="91" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.symtable.SymbolReferenceModel:From Location:Label:Subroutine:Access:From Preview:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.util.table.field.ReferenceFromAddressTableColumn" WIDTH="119" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceFromLabelTableColumn" WIDTH="119" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolReferenceModel$SubroutineTableColumn" WIDTH="118" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolReferenceModel$AccessTableColumn" WIDTH="86" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceFromPreviewTableColumn" WIDTH="151" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceFromFunctionTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceFromBytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceToPreviewTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceToBytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.symtable.SymbolTableModel:Name:Location:Symbol Type:Data Type:Namespace:Source:Reference Count:Offcut Ref Count:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$NameTableColumn" WIDTH="260" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$LocationTableColumn" WIDTH="168" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn" WIDTH="166" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$DataTypeTableColumn" WIDTH="174" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$NamespaceTableColumn" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$SourceTableColumn" WIDTH="170" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$ReferenceCountTableColumn" WIDTH="148" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$OffuctReferenceCountTableColumn" WIDTH="147" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$PinnedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$UserTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="descending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.model.PathTableModel:Path:Key:Value:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathStringColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastKeyColumn.Key" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathValueColumn.Value" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastLifespanColumn.Life" WIDTH="114" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastLifespanPlotColumn.Plot" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.equate.EquateTableModel:Name:Value:# Refs:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="88" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="88" VISIBLE="true" />
                        <COLUMN NAME="# Refs" WIDTH="88" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider$ModuleTableModel:Base Address:Max Address:Name:Module Name:Lifespan:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Base Address" WIDTH="73" VISIBLE="true" />
                        <COLUMN NAME="Max Address" WIDTH="73" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="73" VISIBLE="true" />
                        <COLUMN NAME="Module Name" WIDTH="73" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="72" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="72" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.GTableFilterPanel$SortedTableModelWrapper:In::Name:Description:Category:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="In" WIDTH="30" VISIBLE="true" />
                        <COLUMN NAME="" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="209" VISIBLE="true" />
                        <COLUMN NAME="Description" WIDTH="277" VISIBLE="true" />
                        <COLUMN NAME="Category" WIDTH="141" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.register.RegisterValuesPanel$RegisterValuesTableModel:Start Address:End Address:Value:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Start Address" WIDTH="150" VISIBLE="true" />
                        <COLUMN NAME="End Address" WIDTH="150" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="150" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Name:Lifespan:Start:End:Length:Read:Write:Execute:Volatile:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="122" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="68" VISIBLE="true" />
                        <COLUMN NAME="Start" WIDTH="70" VISIBLE="true" />
                        <COLUMN NAME="End" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="68" VISIBLE="true" />
                        <COLUMN NAME="Read" WIDTH="61" VISIBLE="true" />
                        <COLUMN NAME="Write" WIDTH="67" VISIBLE="true" />
                        <COLUMN NAME="Execute" WIDTH="59" VISIBLE="true" />
                        <COLUMN NAME="Volatile" WIDTH="58" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="GRAPH_DISPLAY_SERVICE" />
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsProvider$RegionTableModel:Name:Lifespan:Start:End:Length:Read:Write:Execute:Volatile:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="Start" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="End" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="Read" WIDTH="31" VISIBLE="true" />
                        <COLUMN NAME="Write" WIDTH="30" VISIBLE="true" />
                        <COLUMN NAME="Execute" WIDTH="31" VISIBLE="true" />
                        <COLUMN NAME="Volatile" WIDTH="31" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Dynamic Address:Static Program:Static Address:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Dynamic Address" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="Static Program" WIDTH="114" VISIBLE="true" />
                        <COLUMN NAME="Static Address" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="114" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider$LogTableModel:Icon:Message:Actions:Time:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Icon" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Message" WIDTH="229" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Actions" WIDTH="128" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Time" WIDTH="94" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="descending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="descending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.BreakpointTableModel:Enabled:Address:Kind:Threads:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Enabled" WIDTH="21" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Kind" WIDTH="205" VISIBLE="true" />
                        <COLUMN NAME="Threads" WIDTH="205" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Start Address:End Address:Section Name:Module Name:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Start Address" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="End Address" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Section Name" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Module Name" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="101" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointTableModel:Enabled:Address:Length:Kinds:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Enabled" WIDTH="41" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="161" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="72" VISIBLE="true" />
                        <COLUMN NAME="Kinds" WIDTH="161" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.references.ExternalNamesTableModel:Name:Ghidra Program:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="219" VISIBLE="true" />
                        <COLUMN NAME="Ghidra Program" WIDTH="218" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Remove:Module:Dynamic Base:Program:Static Base:Size:Choose:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Remove" WIDTH="32" VISIBLE="true" />
                        <COLUMN NAME="Module" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="Dynamic Base" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="Program" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="Static Base" WIDTH="105" VISIBLE="true" />
                        <COLUMN NAME="Size" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="Choose" WIDTH="32" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="KNOWN_EXTENSIONS">
                <ARRAY NAME="KNOWN_EXTENSIONS" TYPE="string" />
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel:Installation Status:Status:Name:Description:Category:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel$PluginInstalledColumn.Installation Status" WIDTH="25" VISIBLE="true" />
                        <COLUMN NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel$PluginStatusColumn.Status" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel$PluginNameColumn.Name" WIDTH="219" VISIBLE="true" />
                        <COLUMN NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel$PluginDescriptionColumn.Description" WIDTH="219" VISIBLE="true" />
                        <COLUMN NAME="ghidra.framework.plugintool.dialog.PluginInstallerTableModel$PluginCategoryColumn.Category" WIDTH="219" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointLocationTableModel:Name:Address:Trace:Threads:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Trace" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Threads" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="101" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider$RegistersTableModel:Fav:#:Name:Value:Type:Repr:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Fav" WIDTH="38" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.#" WIDTH="38" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="63" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Value" WIDTH="122" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Type" WIDTH="72" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Repr" WIDTH="121" VISIBLE="true" />
                        <COLUMN NAME="ghidra.taint.gui.field.TaintDebuggerRegisterColumnFactory$1.Taint" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="descending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider$WatchTableModel:Expression:Address:Data Type:Raw:Value:Error:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Expression" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Data Type" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Raw" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Error" WIDTH="110" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider$RegistersTableModel:#:Name:Value:Type:Repr:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="#" WIDTH="66" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="86" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="133" VISIBLE="true" />
                        <COLUMN NAME="Type" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="Repr" WIDTH="132" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider$SectionTableModel:Start Address:End Address:Section Name:Module Name:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Start Address" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="End Address" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Section Name" WIDTH="88" VISIBLE="true" />
                        <COLUMN NAME="Module Name" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="87" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.register.DebuggerAvailableRegistersDialog$AvailableRegistersTableModel::#:Name:Bits:Known:Group:Contains:Parent:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="" WIDTH="50" VISIBLE="true" />
                        <COLUMN NAME="#" WIDTH="45" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="70" VISIBLE="true" />
                        <COLUMN NAME="Bits" WIDTH="61" VISIBLE="true" />
                        <COLUMN NAME="Known" WIDTH="51" VISIBLE="true" />
                        <COLUMN NAME="Group" WIDTH="70" VISIBLE="true" />
                        <COLUMN NAME="Contains" WIDTH="51" VISIBLE="true" />
                        <COLUMN NAME="Parent" WIDTH="60" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.memory.MemoryMapModel:Name:Start:End:Length:R:W:X:Volatile:Type:Initialized:Source:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Start" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="End" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="R" WIDTH="25" VISIBLE="true" />
                        <COLUMN NAME="W" WIDTH="25" VISIBLE="true" />
                        <COLUMN NAME="X" WIDTH="25" VISIBLE="true" />
                        <COLUMN NAME="Volatile" WIDTH="50" VISIBLE="true" />
                        <COLUMN NAME="Type" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Initialized" WIDTH="60" VISIBLE="true" />
                        <COLUMN NAME="Source" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="102" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.functionwindow.FunctionTableModel:Label:Location:Function Signature:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn" WIDTH="148" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="124" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionSignatureTableColumn" WIDTH="148" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionBodySizeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionPurgeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionCallingConventionTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Snap:Timestamp:Event Thread:Schedule:Description:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Snap" WIDTH="180" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Timestamp" WIDTH="339" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Event Thread" WIDTH="180" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Schedule" WIDTH="201" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Description" WIDTH="338" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider$LogTableModel:Level:Message:Actions:Time:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Level" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Message" WIDTH="230" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Actions" WIDTH="129" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Time" WIDTH="95" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="descending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="descending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.analysis.AnalysisPanel$1:Enabled:Analyzer Name:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Enabled" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Analyzer Name" WIDTH="254" VISIBLE="true" />
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.filechooser.DirectoryTableModel:Filename:Size:Modified:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Filename" WIDTH="230" VISIBLE="true" />
                        <COLUMN NAME="Size" WIDTH="231" VISIBLE="true" />
                        <COLUMN NAME="Modified" WIDTH="230" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackProvider$StackTableModel:Level:PC:Function:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Level" WIDTH="166" VISIBLE="true" />
                        <COLUMN NAME="PC" WIDTH="165" VISIBLE="true" />
                        <COLUMN NAME="Function" WIDTH="165" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="164" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Base Address:Max Address:Module Name:Lifespan:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Base Address" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Max Address" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Module Name" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="102" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="101" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperProvider$UniqueTableModel:Name:Value:Type:Repr:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Type" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="Repr" WIDTH="103" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointLocationTableModel:Enabled:Name:Address:Trace:Threads:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Enabled" WIDTH="18" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="86" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Trace" WIDTH="86" VISIBLE="true" />
                        <COLUMN NAME="Threads" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="87" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadTableModel:Path:Name:Created:Destroyed:State:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadNameColumn.Name" WIDTH="208" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadCreatedColumn.Created" WIDTH="208" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadDestroyedColumn.Destroyed" WIDTH="208" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadStateColumn.State" WIDTH="207" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadCommentColumn.Comment" WIDTH="208" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPlotColumn.Plot" WIDTH="207" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsProvider$ThreadTableModel:Name:Created:Destroyed:State:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Created" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Destroyed" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="State" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="Comment" WIDTH="151" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.datawindow.DataTableModel:Data:Location:Type:Size:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.datawindow.DataTableModel$DataValueTableColumn" WIDTH="122" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="98" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.datawindow.DataTableModel$TypeTableColumn" WIDTH="122" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.datawindow.DataTableModel$SizeTableColumn" WIDTH="78" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionTableModel:Path:Start:End:Name:Module Name:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionPathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionStartColumn.Start" WIDTH="90" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionEndColumn.End" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionNameColumn.Name" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionModuleNameColumn.Module Name" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionLengthColumn.Length" WIDTH="91" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.ErrLogDialog$ErrEntryTableModel:#:Message:Details:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.ErrLogDialog$ErrEntryTableModel$IdColumn.#" WIDTH="331" VISIBLE="true" />
                        <COLUMN NAME="docking.ErrLogDialog$ErrEntryTableModel$MessageColumn.Message" WIDTH="332" VISIBLE="true" />
                        <COLUMN NAME="docking.ErrLogDialog$ErrEntryTableModel$DetailsColumn.Details" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="docking.ErrLogDialog$ErrEntryTableModel$TimestampColumn.Time" WIDTH="331" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.datapreview.DataTypePreviewPlugin$MyTableModel:Name:Preview:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Name" WIDTH="682" VISIBLE="true" />
                        <COLUMN NAME="Preview" WIDTH="681" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Tick:Description:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Tick" WIDTH="321" VISIBLE="true" />
                        <COLUMN NAME="Description" WIDTH="780" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.equate.EquateReferenceTableModel:Ref Addr:Op Index:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Ref Addr" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="Op Index" WIDTH="82" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.GTableFilterPanel$SortedTableModelWrapper:Action Name:KeyBinding:Plugin Name:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Action Name" WIDTH="359" VISIBLE="true" />
                        <COLUMN NAME="KeyBinding" WIDTH="180" VISIBLE="true" />
                        <COLUMN NAME="Plugin Name" WIDTH="179" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleTableModel:Path:Base:Max:Name:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModulePathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleBaseColumn.Base" WIDTH="114" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleMaxColumn.Max" WIDTH="114" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleNameColumn.Name" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleLengthColumn.Length" WIDTH="114" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Remove:Module:Section:Dynamic Base:Program:Block:Static Base:Size:Choose:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Remove" WIDTH="32" VISIBLE="true" />
                        <COLUMN NAME="Module" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Section" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Dynamic Base" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Program" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Block" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Static Base" WIDTH="75" VISIBLE="true" />
                        <COLUMN NAME="Size" WIDTH="74" VISIBLE="true" />
                        <COLUMN NAME="Choose" WIDTH="32" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$StackTableModel:Level:PC:Function:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameLevelColumn.Level" WIDTH="35" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FramePcColumn.PC" WIDTH="315" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameFunctionColumn.Function" WIDTH="314" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.bookmark.BookmarkTableModel:Type:Category:Description:Location:Label:Preview:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.bookmark.BookmarkTableModel$TypeTableColumn" WIDTH="189" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.bookmark.BookmarkTableModel$CategoryTableColumn" WIDTH="204" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.bookmark.BookmarkTableModel$DescriptionTableColumn" WIDTH="313" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="204" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn" WIDTH="189" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn" WIDTH="263" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn" WIDTH="15" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="15" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider$WatchTableModel:Expression:Address:Symbol:Value:Type:Repr:Error:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Expression" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Symbol" WIDTH="95" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Value" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Type" WIDTH="95" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Repr" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Error" WIDTH="94" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperProvider$PcodeTableModel:Sequence:Code:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Sequence" WIDTH="27" VISIBLE="true" />
                        <COLUMN NAME="Code" WIDTH="423" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.model.ObjectTableModel:Key:Value:Life:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn.Key" WIDTH="127" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn.Value" WIDTH="127" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifeColumn.Life" WIDTH="126" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifePlotColumn.Plot" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.listing.DebuggerModuleImportDialog$FileTableModel:Remove:Ignore:Path:Import:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Remove" WIDTH="32" VISIBLE="true" />
                        <COLUMN NAME="Ignore" WIDTH="26" VISIBLE="true" />
                        <COLUMN NAME="Path" WIDTH="368" VISIBLE="true" />
                        <COLUMN NAME="Import" WIDTH="32" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointLocationTableModel:State:Name:Address:Trace:Threads:Comment:Sleigh:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.State" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Trace" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Threads" WIDTH="81" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Comment" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Sleigh" WIDTH="24" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerLegacyModulesPanel$ModuleTableModel:Base Address:Max Address:Name:Module Name:Lifespan:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Base Address" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Max Address" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Module Name" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Lifespan" WIDTH="77" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="76" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$LogicalBreakpointTableModel:State:Name:Address:Image:Length:Kinds:Locations:Sleigh:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.State" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="93" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="93" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Image" WIDTH="63" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="41" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Kinds" WIDTH="92" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Locations" WIDTH="18" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Sleigh" WIDTH="30" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="3" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider$WatchTableModel:Expression:Address:Value:Type:Repr:Error:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Expression" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Type" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Repr" WIDTH="110" VISIBLE="true" />
                        <COLUMN NAME="Error" WIDTH="110" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerLegacyRegionsPanel$RegionTableModel:Name:Lifespan:Start:End:Length:Read:Write:Execute:Volatile:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="106" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Lifespan" WIDTH="106" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Start" WIDTH="106" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.End" WIDTH="106" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="106" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Read" WIDTH="31" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Write" WIDTH="31" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Execute" WIDTH="31" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Volatile" WIDTH="31" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="SymbolTablePlugin">
                <STATE NAME="SELECTION_NAVIGATION_SELECTED_STATE" TYPE="boolean" VALUE="true" />
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperProvider$UniqueTableModel:Ref:Unique:Bytes:Value:Type:Repr:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Ref" WIDTH="45" VISIBLE="true" />
                        <COLUMN NAME="Unique" WIDTH="138" VISIBLE="true" />
                        <COLUMN NAME="Bytes" WIDTH="147" VISIBLE="true" />
                        <COLUMN NAME="Value" WIDTH="138" VISIBLE="true" />
                        <COLUMN NAME="Type" WIDTH="153" VISIBLE="true" />
                        <COLUMN NAME="Repr" WIDTH="153" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="4" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleTableModel:Path:Base:Max:Name:Mapping:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModulePathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleBaseColumn.Base" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleMaxColumn.Max" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleNameColumn.Name" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleMappingColumn.Mapping" WIDTH="91" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleLengthColumn.Length" WIDTH="90" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Snap:Timestamp:Event Thread:Ticks:Description:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Snap" WIDTH="95" VISIBLE="true" />
                        <COLUMN NAME="Timestamp" WIDTH="288" VISIBLE="true" />
                        <COLUMN NAME="Event Thread" WIDTH="287" VISIBLE="true" />
                        <COLUMN NAME="Ticks" WIDTH="286" VISIBLE="true" />
                        <COLUMN NAME="Description" WIDTH="286" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadTableModel:Path:Name:PC:Function:Module:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadNameColumn.Name" WIDTH="248" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPcColumn.PC" WIDTH="248" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadFunctionColumn.Function" WIDTH="247" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadModuleColumn.Module" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadSpColumn.SP" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadStateColumn.State" WIDTH="248" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadCommentColumn.Comment" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPlotColumn.Plot" WIDTH="247" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel:Location:String:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="210" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$DataValueColumn" WIDTH="210" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionBodySizeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionSignatureTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionPurgeTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionCallingConventionTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$LogicalBreakpointTableModel:Enabled:Image:Address:Length:Kinds:Locations:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Enabled" WIDTH="38" VISIBLE="true" />
                        <COLUMN NAME="Image" WIDTH="125" VISIBLE="true" />
                        <COLUMN NAME="Address" WIDTH="61" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="43" VISIBLE="true" />
                        <COLUMN NAME="Kinds" WIDTH="61" VISIBLE="true" />
                        <COLUMN NAME="Locations" WIDTH="123" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.GTableFilterPanel$SortedTableModelWrapper:In Tool:Status:Filename:Description:Key Binding:Full Path:Category:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="In Tool" WIDTH="50" VISIBLE="true" />
                        <COLUMN NAME="Status" WIDTH="50" VISIBLE="true" />
                        <COLUMN NAME="Filename" WIDTH="147" VISIBLE="true" />
                        <COLUMN NAME="Description" WIDTH="245" VISIBLE="true" />
                        <COLUMN NAME="Key Binding" WIDTH="100" VISIBLE="true" />
                        <COLUMN NAME="Full Path" WIDTH="122" VISIBLE="true" />
                        <COLUMN NAME="Category" WIDTH="122" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$StackTableModel:Level:PC:Function:Module:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameLevelColumn.Level" WIDTH="33" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FramePcColumn.PC" WIDTH="209" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameFunctionColumn.Function" WIDTH="209" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameModuleColumn.Module" WIDTH="209" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Dynamic Address:Static Program:Static Address:Length:Shift:Lifespan:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Dynamic Address" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="Static Program" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="Static Address" WIDTH="77" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="76" VISIBLE="true" />
                        <COLUMN NAME="Shift" WIDTH="77" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="76" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.SelectColumnsDialog$SelectColumnsModel:Visible:Column Name:Is Default?:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Visible" WIDTH="30" VISIBLE="true" />
                        <COLUMN NAME="Column Name" WIDTH="179" VISIBLE="true" />
                        <COLUMN NAME="Is Default?" WIDTH="179" VISIBLE="true" />
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerLegacyThreadsPanel$ThreadTableModel:Name:Created:Destroyed:State:Comment:Plot:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="233" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Created" WIDTH="148" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Destroyed" WIDTH="148" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.State" WIDTH="152" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Comment" WIDTH="233" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Plot" WIDTH="332" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.reloc.RelocationTableModel:Location:Type:Values:Original Bytes:Name:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.reloc.RelocationTableModel$RelocationTypeColumn" WIDTH="88" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.reloc.RelocationTableModel$RelocationValueColumn" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.reloc.RelocationTableModel$RelocationBytesColumn" WIDTH="88" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.reloc.RelocationTableModel$RelocationNameColumn" WIDTH="87" VISIBLE="true" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn" WIDTH="75" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn" WIDTH="75" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.pathmanager.PathManagerModel:Use:Path:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Use" WIDTH="50" VISIBLE="true" />
                        <COLUMN NAME="Path" WIDTH="294" VISIBLE="true" />
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.symtable.SymbolTableModel:Name:Location:Type:Data Type:Namespace:Source:Reference Count:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$NameTableColumn.Name" WIDTH="200" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$LocationTableColumn.Location" WIDTH="200" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$SymbolTypeTableColumn.Type" WIDTH="199" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$DataTypeTableColumn.Data Type" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$NamespaceTableColumn.Namespace" WIDTH="200" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$SourceTableColumn.Source" WIDTH="199" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$ReferenceCountTableColumn.Reference Count" WIDTH="200" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$OffcutReferenceCountTableColumn.Offcut Ref Count" WIDTH="199" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$PinnedTableColumn.Pinned" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$UserTableColumn.User" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.symtable.SymbolTableModel$OriginalNameColumn.Original Imported Name" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn.Preview" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.CodeUnitTableColumn.Code Unit" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn.Label" WIDTH="200" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn.Mem Type" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn.Function Name" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn.Location" WIDTH="200" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn.Byte Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn.Namespace" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn.Reference Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.EOLCommentTableColumn.EOL Comment" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn.Param Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn.Offcut Reference Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn.Mem Block" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn.Bytes" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn.Symbol Source" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn.Symbol Type" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Base Address:Max Address:Name:Module Name:Lifespan:Length:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="Base Address" WIDTH="85" VISIBLE="true" />
                        <COLUMN NAME="Max Address" WIDTH="84" VISIBLE="true" />
                        <COLUMN NAME="Name" WIDTH="85" VISIBLE="true" />
                        <COLUMN NAME="Module Name" WIDTH="85" VISIBLE="true" />
                        <COLUMN NAME="Lifespan" WIDTH="85" VISIBLE="true" />
                        <COLUMN NAME="Length" WIDTH="85" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionTableModel:Key:Path:Name:Start:End:Length:Read:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionKeyColumn.Key" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionPathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionNameColumn.Name" WIDTH="141" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionStartColumn.Start" WIDTH="141" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionEndColumn.End" WIDTH="141" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionLengthColumn.Length" WIDTH="141" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionReadColumn.Read" WIDTH="32" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionWriteColumn.Write" WIDTH="32" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionExecuteColumn.Execute" WIDTH="32" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="DEFAULT">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn.Key" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn.Value" WIDTH="115" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifeColumn.Life" WIDTH="114" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifePlotColumn.Plot" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
        </PREFERENCES>
        <EXTENSIONS>
        </EXTENSIONS>
    </TOOL>
</TOOL_CONFIG>

