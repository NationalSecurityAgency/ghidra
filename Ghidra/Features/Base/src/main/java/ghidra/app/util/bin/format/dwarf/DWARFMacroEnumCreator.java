/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;
import java.util.*;

import generic.expressions.*;
import ghidra.app.util.bin.format.dwarf.macro.DWARFMacroHeader;
import ghidra.app.util.bin.format.dwarf.macro.entry.*;
import ghidra.app.util.bin.format.dwarf.macro.entry.DWARFMacroDefine.MacroInfo;
import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Creates Enum data types in the program from DWARF macro info entries. Each macro
 * that can be resolved to a long value results in an Enum datatype with a single 
 * value
 */
public class DWARFMacroEnumCreator {

	private DWARFProgram dprog;
	private Set<String> processedMacros;
	public static final String ENUM_PATH = "_DEFINES_";

	/**
	 * Constructor
	 * @param dprog DWARF Program
	 */
	public DWARFMacroEnumCreator(DWARFProgram dprog) {
		this.dprog = dprog;
		processedMacros = new HashSet<>();
	}

	/**
	 * Creates Ghidra Enums from DWARF macro info entries.
	 * <p>
	 * The enums are placed in the program_name/DWARF/_DEFINES_ category path.
	 * Only one Enum is created for a given name.  Creating multiple
	 * Enums for redefined or multiply-defined macros in not current supported.
	 * Each value in an enum given a comment consisting of the name of the 
	 * corresponding compilation unit.
	 * 
	 * 
	 * @param includeCommandLineDefines if false, macros passed on the command line are ignored
	 * @param monitor monitor
	 * @throws CancelledException if user cancels
	 * @throws IOException if error reading macro info
	 */
	public void createEnumsFromMacroInfo(boolean includeCommandLineDefines, TaskMonitor monitor)
			throws CancelledException, IOException {
		monitor.initialize(dprog.getCompilationUnits().size());
		CategoryPath catPath = DWARFProgram.DWARF_ROOT_CATPATH.extend(ENUM_PATH);
		for (DWARFCompilationUnit cu : dprog.getCompilationUnits()) {
			monitor.increment();
			monitor.setMessage("DWARF: Processing Macros for " + cu.getName());
			Map<String, ExpressionValue> macrosToValues = new HashMap<>();
			createEnums(cu.getMacros(), macrosToValues, catPath, includeCommandLineDefines,
				monitor);
		}
	}

	private void createEnums(DWARFMacroHeader macroHeader,
			Map<String, ExpressionValue> macrosToValues, CategoryPath catPath,
			boolean includeCommandLineDefines, TaskMonitor monitor)
			throws IOException, CancelledException {
		DataTypeManager dtManager = dprog.getGhidraProgram().getDataTypeManager();
		DWARFImportSummary importSummary = dprog.getImportSummary();
		for (DWARFMacroInfoEntry macroEntry : macroHeader.getEntries()) {
			monitor.checkCancelled();
			switch (macroEntry) {
				case DWARFMacroUndef undef:
					macrosToValues.remove(undef.getMacroInfo().symbolName());
					break;
				case DWARFMacroDefine define:
					MacroInfo macroInfo = define.getMacroInfo();
					if (!macroInfo.isFunctionLike()) {
						if (!includeCommandLineDefines && define.getLineNumber() == 0) {
							break;
						}
						String symbolName = macroInfo.symbolName();
						if (processedMacros.contains(symbolName)) {
							break;
						}
						processedMacros.add(symbolName);
						try {
							ExpressionEvaluator evaluator =
								new ExpressionEvaluator(s -> macrosToValues.get(s));
							long value = evaluator.parseAsLong(macroInfo.definition());
							macrosToValues.put(symbolName, new LongExpressionValue(value));
							EnumDataType enumDT =
								new EnumDataType(catPath, "define_" + symbolName, 8,
									dtManager);
							enumDT.add(symbolName, value,
								macroHeader.getCompilationUnit().getName());
							importSummary.numEnumsCreated++;
							enumDT.setLength(enumDT.getMinimumPossibleLength());
							dtManager.addDataType(enumDT,
								DataTypeConflictHandler.KEEP_HANDLER);
						}
						catch (ExpressionException e) {
							// couldn't get numeric value for macro, just skip
						}
					}
					break;
				case DWARFMacroImport importMacro:
					createEnums(importMacro.getImportedMacroHeader(), macrosToValues,
						catPath, includeCommandLineDefines, monitor);
					break;
				default:
					break;
			}
		}
	}

}
