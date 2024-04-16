<?xml version="1.0" encoding="UTF-8"?>
<TOOL_CONFIG CONFIG_NAME="NO_LONGER_USED">
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.Program" />
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.program.model.listing.DataTypeArchive" />
    <SUPPORTED_DATA_TYPE CLASS_NAME="ghidra.trace.model.Trace" />
    <ICON LOCATION="debugger32.png" />
    <TOOL TOOL_NAME="Debugger" INSTANCE_NAME="">
        <OPTIONS />
        <PACKAGE NAME="Ghidra Core">
            <INCLUDE CLASS="ghidra.app.plugin.core.editor.TextEditorManagerPlugin" />
            <INCLUDE CLASS="ghidra.app.plugin.core.interpreter.InterpreterPanelPlugin" />
            <INCLUDE CLASS="ghidra.app.plugin.core.terminal.TerminalPlugin" />
        </PACKAGE>
        <PACKAGE NAME="Debugger">
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.interpreters.DebuggerInterpreterPlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsPlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.gui.target.DebuggerTargetsPlugin" />
            <EXCLUDE CLASS="ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin" />
        </PACKAGE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.debug.gui.model.DebuggerModelPlugin">
            <XML NAME="connectedProvider">
                <SAVE_STATE>
                    <STATE NAME="showAttributesTable" TYPE="boolean" VALUE="false" />
                    <STATE NAME="showElementsTable" TYPE="boolean" VALUE="false" />
                    <STATE NAME="showPrimitivesInTree" TYPE="boolean" VALUE="true" />
                </SAVE_STATE>
            </XML>
        </PLUGIN_STATE>
        <PLUGIN_STATE CLASS="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPlugin">
            <STATE NAME="showSectionsTable" TYPE="boolean" VALUE="false" />
        </PLUGIN_STATE>
        <ROOT_NODE X_POS="1558" Y_POS="4625" WIDTH="1440" HEIGHT="1037" EX_STATE="0" FOCUSED_OWNER="CodeBrowserPlugin" FOCUSED_NAME="Listing" FOCUSED_TITLE="Listing: ">
            <SPLIT_NODE WIDTH="100" HEIGHT="100" DIVIDER_LOCATION="0" ORIENTATION="VERTICAL">
                <SPLIT_NODE WIDTH="100" HEIGHT="100" DIVIDER_LOCATION="0" ORIENTATION="VERTICAL">
                    <SPLIT_NODE WIDTH="1438" HEIGHT="928" DIVIDER_LOCATION="713" ORIENTATION="VERTICAL">
                        <SPLIT_NODE WIDTH="100" HEIGHT="100" DIVIDER_LOCATION="0" ORIENTATION="VERTICAL">
                            <SPLIT_NODE WIDTH="1438" HEIGHT="659" DIVIDER_LOCATION="251" ORIENTATION="HORIZONTAL">
                                <SPLIT_NODE WIDTH="473" HEIGHT="659" DIVIDER_LOCATION="692" ORIENTATION="VERTICAL">
                                    <SPLIT_NODE WIDTH="360" HEIGHT="659" DIVIDER_LOCATION="486" ORIENTATION="VERTICAL">
                                        <COMPONENT_NODE TOP_INFO="1">
                                            <COMPONENT_INFO NAME="Connections" OWNER="TraceRmiConnectionManagerPlugin" TITLE="Connections" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987724" />
                                            <COMPONENT_INFO NAME="Debug Console" OWNER="DebuggerConsolePlugin" TITLE="Debug Console" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304144451936542" />
                                        </COMPONENT_NODE>
                                        <COMPONENT_NODE TOP_INFO="0">
                                            <COMPONENT_INFO NAME="Model" OWNER="DebuggerModelPlugin" TITLE="Model" ACTIVE="true" GROUP="Debugger.Core" INSTANCE_ID="3592304145116733721" />
                                        </COMPONENT_NODE>
                                    </SPLIT_NODE>
                                    <COMPONENT_NODE TOP_INFO="0">
                                        <COMPONENT_INFO NAME="Program Tree" OWNER="ProgramTreePlugin" TITLE="Program Trees" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987730" />
                                    </COMPONENT_NODE>
                                </SPLIT_NODE>
                                <SPLIT_NODE WIDTH="1293" HEIGHT="590" DIVIDER_LOCATION="785" ORIENTATION="VERTICAL">
                                    <SPLIT_NODE WIDTH="1386" HEIGHT="638" DIVIDER_LOCATION="705" ORIENTATION="VERTICAL">
                                        <SPLIT_NODE WIDTH="1074" HEIGHT="659" DIVIDER_LOCATION="561" ORIENTATION="HORIZONTAL">
                                            <SPLIT_NODE WIDTH="600" HEIGHT="659" DIVIDER_LOCATION="475" ORIENTATION="VERTICAL">
                                                <COMPONENT_NODE TOP_INFO="0">
                                                    <COMPONENT_INFO NAME="Listing" OWNER="DebuggerListingPlugin" TITLE="Dynamic" ACTIVE="true" GROUP="Core" INSTANCE_ID="3592304123427987740" />
                                                </COMPONENT_NODE>
                                                <COMPONENT_NODE TOP_INFO="0">
                                                    <COMPONENT_INFO NAME="Listing" OWNER="CodeBrowserPlugin" TITLE="Listing: " ACTIVE="true" GROUP="Core" INSTANCE_ID="3592304123427987738" />
                                                </COMPONENT_NODE>
                                            </SPLIT_NODE>
                                            <COMPONENT_NODE TOP_INFO="13">
                                                <COMPONENT_INFO NAME="Decompiler" OWNER="DecompilePlugin" TITLE="Decompile" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987731" />
                                                <COMPONENT_INFO NAME="Bytes" OWNER="ByteViewerPlugin" TITLE="Bytes: No Program" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987733" />
                                                <COMPONENT_INFO NAME="Data Window" OWNER="DataWindowPlugin" TITLE="Defined Data" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733716" />
                                                <COMPONENT_INFO NAME="Defined Strings" OWNER="ViewStringsPlugin" TITLE="Defined Strings" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733724" />
                                                <COMPONENT_INFO NAME="Equates Table" OWNER="EquateTablePlugin" TITLE="Equates Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987736" />
                                                <COMPONENT_INFO NAME="External Programs" OWNER="ReferencesPlugin" TITLE="External Programs" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987739" />
                                                <COMPONENT_INFO NAME="Functions Window" OWNER="FunctionWindowPlugin" TITLE="Functions" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987742" />
                                                <COMPONENT_INFO NAME="Relocation Table" OWNER="RelocationTablePlugin" TITLE="Relocation Table" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733723" />
                                                <COMPONENT_INFO NAME="Modules" OWNER="DebuggerModulesPlugin" TITLE="Modules" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733703" />
                                                <COMPONENT_INFO NAME="Registers" OWNER="DebuggerRegistersPlugin" TITLE="Registers" ACTIVE="true" GROUP="Debugger.Core" INSTANCE_ID="3592304145116733725" />
                                                <COMPONENT_INFO NAME="Script Manager" OWNER="GhidraScriptMgrPlugin" TITLE="Script Manager" ACTIVE="false" GROUP="Script Group" INSTANCE_ID="3592304123427987727" />
                                                <COMPONENT_INFO NAME="Listing" OWNER="DebuggerListingPlugin" TITLE="[Dynamic]" ACTIVE="false" GROUP="Core" INSTANCE_ID="3562758574866164514" />
                                                <COMPONENT_INFO NAME="Memory" OWNER="DebuggerMemoryBytesPlugin" TITLE="Memory" ACTIVE="true" GROUP="disconnected" INSTANCE_ID="3592304123427987713" />
                                                <COMPONENT_INFO NAME="Breakpoints" OWNER="DebuggerBreakpointsPlugin" TITLE="Breakpoints" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733722" />
                                            </COMPONENT_NODE>
                                        </SPLIT_NODE>
                                        <SPLIT_NODE WIDTH="1386" HEIGHT="189" DIVIDER_LOCATION="495" ORIENTATION="HORIZONTAL">
                                            <COMPONENT_NODE TOP_INFO="0">
                                                <COMPONENT_INFO NAME="Data Type Preview" OWNER="DataTypePreviewPlugin" TITLE="Data Type Preview" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304144451936539" />
                                            </COMPONENT_NODE>
                                            <COMPONENT_NODE TOP_INFO="0">
                                                <COMPONENT_INFO NAME="Virtual Disassembler - Current Instruction" OWNER="DisassembledViewPlugin" TITLE="Disassembled View" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987735" />
                                            </COMPONENT_NODE>
                                        </SPLIT_NODE>
                                    </SPLIT_NODE>
                                    <COMPONENT_NODE TOP_INFO="0">
                                        <COMPONENT_INFO NAME="Bookmarks" OWNER="BookmarkPlugin" TITLE="Bookmarks" ACTIVE="false" GROUP="Core.Bookmarks" INSTANCE_ID="3592304123427987729" />
                                    </COMPONENT_NODE>
                                </SPLIT_NODE>
                            </SPLIT_NODE>
                            <COMPONENT_NODE TOP_INFO="0">
                                <COMPONENT_INFO NAME="Function Call Trees" OWNER="CallTreePlugin" TITLE="Function Call Trees" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987726" />
                            </COMPONENT_NODE>
                        </SPLIT_NODE>
                        <SPLIT_NODE WIDTH="1438" HEIGHT="265" DIVIDER_LOCATION="347" ORIENTATION="HORIZONTAL">
                            <COMPONENT_NODE TOP_INFO="1">
                                <COMPONENT_INFO NAME="Regions" OWNER="DebuggerRegionsPlugin" TITLE="Regions" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733719" />
                                <COMPONENT_INFO NAME="Stack" OWNER="DebuggerStackPlugin" TITLE="Stack" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304144451936540" />
                                <COMPONENT_INFO NAME="Console" OWNER="ConsolePlugin" TITLE="Console" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987732" />
                                <COMPONENT_INFO NAME="Watches" OWNER="DebuggerWatchesPlugin" TITLE="Watches" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987723" />
                                <COMPONENT_INFO NAME="Symbol Tree" OWNER="SymbolTreePlugin" TITLE="Symbol Tree" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304123427987725" />
                                <COMPONENT_INFO NAME="DataTypes Provider" OWNER="DataTypeManagerPlugin" TITLE="Data Type Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733699" />
                            </COMPONENT_NODE>
                            <COMPONENT_NODE TOP_INFO="4">
                                <COMPONENT_INFO NAME="Time" OWNER="DebuggerTimePlugin" TITLE="Time" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733713" />
                                <COMPONENT_INFO NAME="Pcode Stepper" OWNER="DebuggerPcodeStepperPlugin" TITLE="Pcode Stepper" ACTIVE="false" GROUP="Default" INSTANCE_ID="3562427531381347481" />
                                <COMPONENT_INFO NAME="Static Mappings" OWNER="DebuggerStaticMappingPlugin" TITLE="Static Mappings" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733720" />
                                <COMPONENT_INFO NAME="Instruction Info" OWNER="ShowInstructionInfoPlugin" TITLE="Instruction Info" ACTIVE="false" GROUP="Default" INSTANCE_ID="3565288898725030387" />
                                <COMPONENT_INFO NAME="Threads" OWNER="DebuggerThreadsPlugin" TITLE="Threads" ACTIVE="true" GROUP="Default" INSTANCE_ID="3592304145116733701" />
                                <COMPONENT_INFO NAME="Terminal" OWNER="TerminalPlugin" TITLE="Terminal" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592298490728135873" />
                            </COMPONENT_NODE>
                        </SPLIT_NODE>
                    </SPLIT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Diff Location Details" OWNER="ProgramDiffPlugin" TITLE="Diff Details" ACTIVE="false" GROUP="Default" INSTANCE_ID="3446095744544693813" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Diff Apply Settings" OWNER="ProgramDiffPlugin" TITLE="Diff Apply Settings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3446095765262458400" />
                </COMPONENT_NODE>
            </SPLIT_NODE>
            <WINDOW_NODE X_POS="423" Y_POS="144" WIDTH="927" HEIGHT="370">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memory Map" OWNER="MemoryMapPlugin" TITLE="Memory Map" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987714" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="2042" Y_POS="4332" WIDTH="1020" HEIGHT="1038">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Graph" OWNER="FunctionGraphPlugin" TITLE="Function Graph" ACTIVE="false" GROUP="Function Graph" INSTANCE_ID="3592304145116733726" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="550" Y_POS="206" WIDTH="655" HEIGHT="509">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Register Manager" OWNER="RegisterPlugin" TITLE="Register Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987741" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="287" Y_POS="186" WIDTH="1424" HEIGHT="666">
                <SPLIT_NODE WIDTH="1408" HEIGHT="559" DIVIDER_LOCATION="573" ORIENTATION="HORIZONTAL">
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Symbol Table" OWNER="SymbolTablePlugin" TITLE="Symbol Table" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3592304145116733717" />
                    </COMPONENT_NODE>
                    <COMPONENT_NODE TOP_INFO="0">
                        <COMPONENT_INFO NAME="Symbol References" OWNER="SymbolTablePlugin" TITLE="Symbol References" ACTIVE="false" GROUP="symbolTable" INSTANCE_ID="3592304145116733718" />
                    </COMPONENT_NODE>
                </SPLIT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Checksum Generator" OWNER="ComputeChecksumsPlugin" TITLE="Checksum Generator" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987737" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Tags" OWNER="FunctionTagPlugin" TITLE="Function Tags" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733700" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="-1" Y_POS="-1" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Comment Window" OWNER="CommentWindowPlugin" TITLE="Comments" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733715" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="1792" Y_POS="1234" WIDTH="559" HEIGHT="480">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Python" OWNER="InterpreterPanelPlugin" TITLE="Python" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733702" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Function Call Graph" OWNER="FunctionCallGraphPlugin" TITLE="Function Call Graph" ACTIVE="false" GROUP="Function Call Graph" INSTANCE_ID="3592304144451936541" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="658" Y_POS="1489" WIDTH="470" HEIGHT="540">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memory Range Mappings" OWNER="DebuggerStaticMappingPlugin" TITLE="Memory Range Mappings" ACTIVE="false" GROUP="Default" INSTANCE_ID="3367472270453938012" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="BundleManager" OWNER="GhidraScriptMgrPlugin" TITLE="Bundle Manager" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304123427987728" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
            <WINDOW_NODE X_POS="0" Y_POS="0" WIDTH="0" HEIGHT="0">
                <COMPONENT_NODE TOP_INFO="0">
                    <COMPONENT_INFO NAME="Memview" OWNER="DebuggerMemviewPlugin" TITLE="Memview" ACTIVE="false" GROUP="Default" INSTANCE_ID="3592304145116733714" />
                </COMPONENT_NODE>
            </WINDOW_NODE>
        </ROOT_NODE>
        <PREFERENCES>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider$LogTableModel:Icon:Message:Actions:Time:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Icon" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Message" WIDTH="190" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Actions" WIDTH="89" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Time" WIDTH="55" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="descending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="descending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider$BreakpointLocationTableModel:State:Name:Address:Trace:Threads:Comment:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.State" WIDTH="24" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Trace" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Threads" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Comment" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Sleigh" WIDTH="30" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
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
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleTableModel:Path:Base:Max:Name:Mapping:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModulePathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleBaseColumn.Base" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleMaxColumn.Max" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleNameColumn.Name" WIDTH="93" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleMappingColumn.Mapping" WIDTH="94" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesPanel$ModuleLengthColumn.Length" WIDTH="93" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadTableModel:Path:Name:PC:Function:Module:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPathColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadNameColumn.Name" WIDTH="187" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPcColumn.PC" WIDTH="187" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadFunctionColumn.Function" WIDTH="187" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadModuleColumn.Module" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadSpColumn.SP" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadStateColumn.State" WIDTH="187" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadCommentColumn.Comment" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel$ThreadPlotColumn.Plot" WIDTH="186" VISIBLE="true" />
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
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionStartColumn.Start" WIDTH="15" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionEndColumn.End" WIDTH="15" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionNameColumn.Name" WIDTH="15" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionModuleNameColumn.Module Name" WIDTH="15" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionsPanel$SectionLengthColumn.Length" WIDTH="15" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.model.PathTableModel:Path:Key:Value:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathStringColumn.Path" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastKeyColumn.Key" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathValueColumn.Value" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastLifespanColumn.Life" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TracePathLastLifespanPlotColumn.Plot" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider$RegistersTableModel:Fav:#:Name:Value:Type:Repr:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Fav" WIDTH="41" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.#" WIDTH="41" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="67" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Value" WIDTH="126" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Type" WIDTH="67" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Repr" WIDTH="126" VISIBLE="true" />
                        <COLUMN NAME="ghidra.taint.gui.field.TaintDebuggerRegisterColumnFactory$1.Taint" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="descending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="1" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.modules.DebuggerStaticMappingProvider$MappingTableModel:Dynamic Address:Static Program:Static Address:Length:Shift:Lifespan:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Dynamic Address" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Static Program" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Static Address" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="155" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Shift" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Lifespan" WIDTH="155" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider$WatchTableModel:Expression:Address:Symbol:Value:Type:Repr:Error:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Expression" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Symbol" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Value" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Type" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Repr" WIDTH="71" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Error" WIDTH="70" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$StackTableModel:Level:PC:Function:Module:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameLevelColumn.Level" WIDTH="28" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FramePcColumn.PC" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameFunctionColumn.Function" WIDTH="156" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.stack.DebuggerStackPanel$FrameModuleColumn.Module" WIDTH="156" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.debug.gui.model.ObjectTableModel:Key:Value:Life:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueKeyColumn.Key" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueValColumn.Value" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifeColumn.Life" WIDTH="82" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.model.columns.TraceValueLifePlotColumn.Plot" WIDTH="500" VISIBLE="false" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="0" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="2" SORT_DIRECTION="ascending" SORT_ORDER="2" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
            <PREFERENCE_STATE NAME="GRAPH_DISPLAY_SERVICE" />
            <PREFERENCE_STATE NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel:Location:String Value:String Representation:Data Type:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$DataLocationColumn.Location" WIDTH="117" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$DataValueColumn.String Value" WIDTH="117" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$StringRepColumn.String Representation" WIDTH="117" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$DataTypeColumn.Data Type" WIDTH="117" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$IsAsciiColumn.Is Ascii" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$CharsetColumn.Charset" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$HasEncodingErrorColumn.Has Encoding Error" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$UnicodeScriptColumn.Unicode Script" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.app.plugin.core.strings.ViewStringsTableModel$TranslatedValueColumn.Translated Value" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.PreviewTableColumn.Preview" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.AddressTableColumn.Location" WIDTH="200" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ByteCountProgramLocationBasedTableColumn.Byte Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.EOLCommentTableColumn.EOL Comment" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionSignatureTableColumn.Function Signature" WIDTH="200" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.OffcutReferenceCountToAddressTableColumn.Offcut Reference Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.IsFunctionNonReturningTableColumn.Non-returning" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.BytesTableColumn.Bytes" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SourceTypeTableColumn.Symbol Source" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.SymbolTypeTableColumn.Symbol Type" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionTagTableColumn.Tags" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.IsFunctionInlineTableColumn.Inline" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.IsFunctionVarargsTableColumn.Varargs" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.CodeUnitTableColumn.Code Unit" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.LabelTableColumn.Label" WIDTH="200" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionCallingConventionTableColumn.Function Calling Convention" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemoryTypeProgramLocationBasedTableColumn.Mem Type" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionNameTableColumn.Function Name" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionPurgeTableColumn.Function Purge" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.NamespaceTableColumn.Namespace" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.ReferenceCountToAddressTableColumn.Reference Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.IsFunctionCustomStorageTableColumn.Custom Storage" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionParameterCountTableColumn.Param Count" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.MemorySectionProgramLocationBasedTableColumn.Mem Block" WIDTH="500" VISIBLE="false" />
                        <COLUMN NAME="ghidra.util.table.field.FunctionBodySizeTableColumn.Function Size" WIDTH="500" VISIBLE="false" />
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
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Name" WIDTH="96" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Address" WIDTH="96" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Image" WIDTH="66" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Length" WIDTH="42" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Kinds" WIDTH="96" VISIBLE="true" />
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
            <PREFERENCE_STATE NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel:Snap:Timestamp:Event Thread:Schedule:Description:">
                <XML NAME="COLUMN_DATA">
                    <Table_State>
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Snap" WIDTH="119" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Timestamp" WIDTH="279" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Event Thread" WIDTH="119" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Schedule" WIDTH="139" VISIBLE="true" />
                        <COLUMN NAME="docking.widgets.table.DefaultEnumeratedColumnTableModel$EnumeratedDynamicTableColumn.Description" WIDTH="278" VISIBLE="true" />
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
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionNameColumn.Name" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionStartColumn.Start" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionEndColumn.End" WIDTH="104" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionLengthColumn.Length" WIDTH="103" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionReadColumn.Read" WIDTH="27" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionWriteColumn.Write" WIDTH="27" VISIBLE="true" />
                        <COLUMN NAME="ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsPanel$RegionExecuteColumn.Execute" WIDTH="27" VISIBLE="true" />
                        <TABLE_SORT_STATE>
                            <COLUMN_SORT_STATE COLUMN_MODEL_INDEX="3" SORT_DIRECTION="ascending" SORT_ORDER="1" />
                        </TABLE_SORT_STATE>
                    </Table_State>
                </XML>
            </PREFERENCE_STATE>
        </PREFERENCES>
    </TOOL>
</TOOL_CONFIG>

