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
package ghidra.app.util.bin.format.dwarf4.next;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.*;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunction.CommitMode;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Iterates through all DIEAs in a {@link DWARFProgram} and creates Ghidra functions
 * and variables.
 */
public class DWARFFunctionImporter {

	/**
	 * Inline funcs shorter than this value receive comments at EOL instead of PRE
	 * (ie. inline funcs that reduce down to a single operand or operand value)
	 */
	private static final int INLINE_FUNC_SHORT_LEN = 8;

	private final DWARFProgram prog;
	private final Program currentProgram;
	private final DWARFDataTypeManager dwarfDTM;
	private final DWARFImportOptions importOptions;
	private final DWARFImportSummary importSummary;

	private ProgramModule rootModule;// Program tree module for DWARF
	private Set<Long> processedOffsets = new HashSet<>();
	private Set<Address> functionsProcessed = new HashSet<>();
	private Set<Address> variablesProcesesed = new HashSet<>();

	private TaskMonitor monitor;

	public static boolean hasDWARFProgModule(Program prog, String progModuleName) {
		ProgramModule dwarfModule = prog.getListing().getRootModule(progModuleName);

		return dwarfModule != null;
	}

	public DWARFFunctionImporter(DWARFProgram prog, TaskMonitor monitor) {
		this.prog = prog;
		this.monitor = monitor;
		this.currentProgram = prog.getGhidraProgram();
		this.dwarfDTM = prog.getDwarfDTM();
		this.importOptions = prog.getImportOptions();
		this.importSummary = prog.getImportSummary();
	}

	private boolean shouldProcess(DIEAggregate diea) {
		if (processedOffsets.contains(diea.getOffset())) {
			return false;
		}
		processedOffsets.add(diea.getOffset());
		return true;
	}

	public void importFunctions() throws CancelledException {
		rootModule = currentProgram.getListing().getRootModule(DWARFProgram.DWARF_ROOT_NAME);
		if (rootModule == null) {
			try {
				rootModule =
					currentProgram.getListing().createRootModule(DWARFProgram.DWARF_ROOT_NAME);
			}
			catch (DuplicateNameException e) {
				// should not happen
			}
		}

		monitor.initialize(prog.getTotalAggregateCount(), "DWARF - Create Funcs & Symbols");
		for (DIEAggregate diea : prog.allAggregates()) {
			monitor.increment();

			try {
				switch (diea.getTag()) {
					case DW_TAG_gnu_call_site: // needs skip head
					case DW_TAG_call_site:
						diea = DIEAggregate.createSkipHead(diea); // fallthru to next switch case
					case DW_TAG_subprogram:    // normal
						try {
							processSubprogram(diea);
						}
						catch (InvalidInputException e) {
							Msg.error(this, "Failed to process subprog " + diea.getHexOffset(), e);
						}
						break;
					case DW_TAG_variable:
						// only process variable definitions that are static variables
						// (ie. they are children of the compunit root, ie. depth == 1).
						// Local variables should be children of dw_tag_subprograms
						// and will be handled in processFuncChildren()
						if (diea.getDepth() == 1) {
							outputGlobal(DWARFVariable.readGlobalVariable(diea));
						}
						break;
					case DW_TAG_label:
						processLabel(diea);
						break;
				}
			}
			catch (OutOfMemoryError oom) {
				throw oom;
			}
			catch (Throwable th) {
				Msg.error(this, "Error when processing DWARF information for DIE %x"
						.formatted(diea.getOffset()),
					th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}
		logImportErrorSummary();


	}

	private void logImportErrorSummary() {
		if (!importSummary.unknownRegistersEncountered.isEmpty()) {
			Msg.error(this, "Found %d unknown registers referenced in DWARF expression operands:"
					.formatted(importSummary.unknownRegistersEncountered.size()));
			List<Integer> sortedUnknownRegs =
				new ArrayList<>(importSummary.unknownRegistersEncountered);
			Collections.sort(sortedUnknownRegs);
			Msg.error(this, "  unknown registers: %s".formatted(sortedUnknownRegs));
		}
	}

	private void markAllChildrenAsProcessed(DebugInfoEntry die) {
		for (DebugInfoEntry child : die.getChildren()) {
			processedOffsets.add(child.getOffset());
			markAllChildrenAsProcessed(child);
		}
	}

	private void processSubprogram(DIEAggregate diea)
			throws IOException, InvalidInputException, DWARFExpressionException {

		if (diea == null || !shouldProcess(diea)) {
			return;
		}

		// read the dwarf function info (name, addr, params)
		DWARFFunction dfunc = DWARFFunction.read(diea);
		if (dfunc == null) {
			markAllChildrenAsProcessed(diea.getHeadFragment());
			return;
		}

		FunctionDefinition origFuncDef = dfunc.asFunctionDefinition(true); // before any fixups

		if (functionsProcessed.contains(dfunc.address)) {
			markAllChildrenAsProcessed(dfunc.diea.getHeadFragment());

			Function currentFunction = currentProgram.getListing().getFunctionAt(dfunc.address);
			if (currentFunction != null) {
				decorateFunctionWithAlternateInfo(dfunc, currentFunction, origFuncDef);
			}
			return;
		}
		functionsProcessed.add(dfunc.address);

		// only process the children (lexical blocks, local vars, etc) if we are going
		// to emit a new ghidra function, otherwise if 2 dwarf function defs point to same
		// location, we will get multiple side-effect output from processFuncChildren
		processFuncChildren(diea, dfunc, 0);

		if (!dfunc.syncWithExistingGhidraFunction(true)) {
			// if false, the stub ghidra function could not be found or created
			return;
		}

		dfunc.runFixups();

		decorateFunctionWithDWARFInfo(dfunc, origFuncDef);

		if (dfunc.signatureCommitMode != CommitMode.SKIP) {
			dfunc.updateFunctionSignature();
		}
		else {
			Msg.warn(this,
				"Failed to get DWARF function signature information, leaving undefined: %s@%s"
						.formatted(dfunc.function.getName(), dfunc.function.getEntryPoint()));
			//Msg.debug(this, "DIE info: " + diea.toString());
		}

		for (DWARFVariable localVar : dfunc.localVars) {
			if (localVar.isRamStorage()) {
				outputGlobal(localVar); // static variable scoped to the function
			}
			else {
				dfunc.commitLocalVariable(localVar);
			}
		}

		if (importOptions.isCreateFuncSignatures()) {
			DataType funcDefDT = dfunc.asFunctionDefinition(false);
			funcDefDT = prog.getGhidraProgram()
					.getDataTypeManager()
					.addDataType(funcDefDT, DWARFDataTypeConflictHandler.INSTANCE);

			// Look for the source info in the funcdef die and fall back to its
			// parent's source info (handles auto-generated ctors and such)
			dwarfDTM.addDataType(diea.getOffset(), funcDefDT,
				DWARFSourceInfo.getSourceInfoWithFallbackToParent(diea));

		}

	}

	private void decorateFunctionWithAlternateInfo(DWARFFunction dfunc, Function gfunc,
			FunctionDefinition funcDef) {
		// Don't include the calling conv as it generates excessive false positives
		// because we haven't run the dfunc through any fixups yet.
		// Unnamed parameters still cause false positives because they render differently between
		// funcdefs and actual functions
		String newAlternatePrototype = funcDef.getPrototypeString(false);

		String currentPrototype = gfunc.getSignature(true).getPrototypeString(false);
		if (!currentPrototype.equals(newAlternatePrototype)) {
			appendPlateComment(dfunc.address, "DWARF alternate signature: ", newAlternatePrototype);
		}

	}
	
	private void decorateFunctionWithDWARFInfo(DWARFFunction dfunc,
			FunctionDefinition origFuncDef) {
		if (dfunc.sourceInfo != null) {
			// Move the function into the program tree of the file
			moveIntoFragment(dfunc.function.getName(), dfunc.address,
				dfunc.highAddress != null ? dfunc.highAddress : dfunc.address.add(1),
				dfunc.sourceInfo.getFilename());

			if (importOptions.isOutputSourceLocationInfo()) {
				appendPlateComment(dfunc.address, "", dfunc.sourceInfo.getDescriptionStr());
			}
		}
		if (importOptions.isOutputDIEInfo()) {
			appendPlateComment(dfunc.address, "DWARF DIE: ", dfunc.diea.getHexOffset());
			appendPlateComment(dfunc.address, "DWARF signature update mode: ",
				dfunc.signatureCommitMode.toString());
		}

		if (dfunc.name.isNameModified()) {
			appendPlateComment(dfunc.address, "DWARF original name: ",
				dfunc.name.getOriginalName());
		}

		FunctionDefinition newFuncDef = dfunc.asFunctionDefinition(true);
		String origFuncDefStr = origFuncDef.getPrototypeString(true);
		if (!newFuncDef.getPrototypeString(true).equals(origFuncDefStr)) {
			// if the prototype of the function was modified during the fixup phase, append
			// the original version (according to dwarf) to the comment
			appendPlateComment(dfunc.address, "DWARF original prototype: ", origFuncDefStr);
		}


	}

	private void processFuncChildren(DIEAggregate diea, DWARFFunction dfunc,
			long offsetFromFuncStart)
			throws InvalidInputException, IOException, DWARFExpressionException {
		// offsetFromFuncStart will be -1 if the containing block didn't have location info

		for (DebugInfoEntry childEntry : diea.getHeadFragment().getChildren()) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);

			switch (childDIEA.getTag()) {
				case DW_TAG_variable: {
					if (offsetFromFuncStart >= 0) {
						DWARFVariable localVar =
							DWARFVariable.readLocalVariable(childDIEA, dfunc, offsetFromFuncStart);
						if (localVar != null) {
							if (prog.getImportOptions().isImportLocalVariables() ||
								localVar.isRamStorage()) {
								// only retain the local var if option is turned on, or global/static variable
								dfunc.localVars.add(localVar);
							}
						}
					}
					break;
				}
				case DW_TAG_lexical_block:
					processLexicalBlock(childDIEA, dfunc);
					break;
				case DW_TAG_label:
					processLabel(childDIEA);
					break;
				case DW_TAG_inlined_subroutine:
					processInlinedSubroutine(childDIEA, dfunc);
					break;

				case DW_TAG_gnu_call_site:
				case DW_TAG_call_site:
					DIEAggregate partDIEA = DIEAggregate.createSkipHead(diea);
					processSubprogram(partDIEA);
					break;

			}
		}
	}

	private void outputGlobal(DWARFVariable globalVar) {
		if (globalVar == null) {
			return;
		}

		Namespace namespace = globalVar.name.getParentNamespace(currentProgram);
		String name = globalVar.name.getName();
		Address address = globalVar.getRamAddress();
		DataType dataType = globalVar.type;

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Symbol labelSym = null;

		if (!currentProgram.getMemory().contains(address)) {
			if (!globalVar.isZeroByte()) {
				Msg.error(this, "Invalid location for global variable %s:%s @%s".formatted(name,
					dataType.getName(), address));
			}
			return;
		}

		if (globalVar.isZeroByte() || !variablesProcesesed.contains(address)) {
			try {
				labelSym = symbolTable.createLabel(address, name, namespace, SourceType.IMPORTED);
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Error creating label for global variable %s/%s at %s"
						.formatted(namespace, name, address));
				return;
			}
		}

		if (globalVar.isZeroByte()) {
			// because this is a zero-length data type (ie. array[0]),
			// don't create a variable at the location since it will prevent other elements
			// from occupying the same offset
			appendComment(address, CodeUnit.PRE_COMMENT,
				"Zero length variable: %s: %s".formatted(name, dataType.getDisplayName()), "\n");

			return;
		}

		if (variablesProcesesed.contains(address)) {
			return;
		}

		labelSym.setPrimary();

		if (globalVar.isExternal) {
			setExternalEntryPoint(true, address);
		}

		if (dataType instanceof Dynamic || dataType instanceof FactoryDataType) {
			appendComment(address, CodeUnit.EOL_COMMENT,
				"Unsupported dynamic data type: " + dataType, "\n");
			dataType = Undefined.getUndefinedDataType(1);
		}
		DWARFDataInstanceHelper dih = new DWARFDataInstanceHelper(currentProgram);
		if (!dih.isDataTypeCompatibleWithAddress(dataType, address)) {
			appendComment(address, CodeUnit.EOL_COMMENT,
				"Could not place DWARF static variable %s: %s @%s because existing data type conflicts."
						.formatted(name, dataType.getName(), address),
				"\n");
		}
		else {
			try {
				Data varData = DataUtilities.createData(currentProgram, address, dataType, -1,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				if (varData != null && globalVar.sourceInfo != null) {
					moveIntoFragment(name, varData.getMinAddress(), varData.getMaxAddress(),
						globalVar.sourceInfo.getFilename());
				}
				variablesProcesesed.add(address);
				importSummary.globalVarsAdded++;
			}
			catch (CodeUnitInsertionException e) {
				Msg.error(this, "Error creating global variable %s:%s @%s: %s".formatted(name,
					dataType.getName(), address, e.getMessage()));
			}
		}

		if (globalVar.sourceInfo != null) {
			appendComment(address, CodeUnit.EOL_COMMENT, globalVar.sourceInfo.getDescriptionStr(),
				"\n");
		}
	}

	/*
	 * Process lexical block entries inside of a function.
	 * 
	 * This recursively processes any children of the lexical block diea via processFuncChildren().
	 */
	private void processLexicalBlock(DIEAggregate diea, DWARFFunction dfunc)
			throws IOException, InvalidInputException, DWARFExpressionException {
		if (!shouldProcess(diea)) {
			return;
		}

		Number lowPC = null;
		boolean disjoint = false;

		// TODO: Do we need to setup the correct frame base based on the
		// location of this lexical block?

		// Process low and high pc if it exists
		if (diea.hasAttribute(DW_AT_low_pc) && diea.hasAttribute(DW_AT_high_pc)) {
			lowPC = diea.getLowPC(0);
		}
		// Otherwise process a range list
		else if (diea.hasAttribute(DW_AT_ranges)) {
			List<DWARFRange> ranges = diea.parseDebugRange(DW_AT_ranges);

			// No range found
			if (ranges.isEmpty()) {
				return;
			}

			lowPC = ranges.get(0).getFrom();
			disjoint = ranges.size() > 1;
		}
		Address blockStart = lowPC != null ? prog.getCodeAddress(lowPC) : null;
		if (blockStart != null && importOptions.isOutputLexicalBlockComments()) {
			DWARFNameInfo dni = prog.getName(diea);
			appendComment(blockStart, CodeUnit.PRE_COMMENT,
				"Begin: " + dni.getName() + (disjoint ? " - Disjoint" : ""), "\n");
		}

		processFuncChildren(diea, dfunc,
			blockStart != null ? blockStart.subtract(dfunc.address) : -1);
	}

	private void processInlinedSubroutine(DIEAggregate diea, DWARFFunction dfunc)
			throws IOException, InvalidInputException, DWARFExpressionException {
		if (!shouldProcess(diea)) {
			return;
		}

		Number lowPC = null;
		Number highPC = null;

		// Process low and high pc if it exists
		if (diea.hasAttribute(DW_AT_low_pc) && diea.hasAttribute(DW_AT_high_pc)) {
			lowPC = diea.getLowPC(0);
			highPC = diea.getHighPC();
		}
		// Otherwise process a range list
		else if (diea.hasAttribute(DW_AT_ranges)) {
			List<DWARFRange> ranges = diea.parseDebugRange(DW_AT_ranges);

			// No range found
			if (ranges.isEmpty()) {
				return;
			}

			lowPC = ranges.get(0).getFrom();
			highPC = ranges.get(ranges.size() - 1).getTo();
		}
		else {
			return;
		}

		Address startAddr = prog.getCodeAddress(lowPC);
		Address endAddr = prog.getCodeAddress(highPC);
		if (importOptions.isOutputInlineFuncComments()) {
			addCommentsForInlineFunc(diea, startAddr, endAddr);
		}

		processFuncChildren(diea, dfunc, startAddr.subtract(dfunc.address));
	}

	/*
	 * Constructs a function def signature for the function and adds it as a comment, either
	 * EOL or PRE depending on how small the inline func is.
	 */
	private void addCommentsForInlineFunc(DIEAggregate diea, Address blockStart, Address blockEnd) {
		FunctionDefinition funcDef = dwarfDTM.getFunctionSignature(diea);
		if (funcDef != null) {
			long inlineFuncLen = blockEnd.subtract(blockStart);
			boolean isShort = inlineFuncLen < INLINE_FUNC_SHORT_LEN;
			if (isShort) {
				appendComment(blockStart, CodeUnit.EOL_COMMENT,
					"inline " + funcDef.getPrototypeString(), "; ");
			}
			else {
				appendComment(blockStart, CodeUnit.PRE_COMMENT,
					"Begin: inline " + funcDef.getPrototypeString(), "\n");
			}
		}
	}

	private void appendComment(Address address, int commentType, String comment, String sep) {
		DWARFUtil.appendComment(currentProgram, address, commentType, "", comment, sep);
	}

	private void appendPlateComment(Address address, String prefix, String comment) {
		DWARFUtil.appendComment(currentProgram, address, CodeUnit.PLATE_COMMENT, prefix, comment,
			"\n");
	}

	/**
	 * Set external entry point.  If declared external add as entry pointer, otherwise
	 * clear as entry point if previously addeds.
	 * @param external true if declared external and false otherwise
	 * @param address address of the entry point
	 */
	private void setExternalEntryPoint(boolean external, Address address) {
		if (external) {
			currentProgram.getSymbolTable().addExternalEntryPoint(address);
		}
		else {
			currentProgram.getSymbolTable().removeExternalEntryPoint(address);
		}
	}

	/**
	 * Move an address range into a fragment.
	 * @param cu current compile unit
	 * @param name name of the fragment
	 * @param start start address of the fragment
	 * @param end end address of the fragment
	 * @param fileID offset of the file name in the debug_line section
	 */
	private void moveIntoFragment(String name, Address start, Address end, String fileName) {
		if (fileName != null) {
			ProgramModule module = null;
			int index = rootModule.getIndex(fileName);
			if (index == -1) {
				try {
					module = rootModule.createModule(fileName);
				}
				catch (DuplicateNameException e) {
					Msg.error(this,
						"Error while moving fragment " + name + " from " + start + " to " + end, e);
					return;
				}
			}
			else {
				Group[] children = rootModule.getChildren();//TODO add a getChildAt(index) method...
				module = (ProgramModule) children[index];
			}
			if (module != null) {
				try {
					ProgramFragment frag = null;
					index = module.getIndex(name);
					if (index == -1) {
						frag = module.createFragment(name);
					}
					else {
						Group[] children = module.getChildren();//TODO add a getChildAt(index) method...
						frag = (ProgramFragment) children[index];
					}
					frag.move(start, end);
				}
				catch (NotFoundException e) {
					Msg.error(this, "Error moving fragment from " + start + " to " + end, e);
					return;
				}
				catch (DuplicateNameException e) {
					//TODO: Thrown by createFragment if fragment name exists in any other module
				}
			}
		}
	}

	private Function createFunction(DWARFFunction dfunc, DIEAggregate diea) {
		try {
			// create a new symbol if one does not exist (symbol table will figure this out)
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			symbolTable.createLabel(dfunc.address, dfunc.name.getName(), dfunc.namespace,
				SourceType.IMPORTED);

			// force new label to become primary (if already a function it will become function name)
			SetLabelPrimaryCmd cmd =
				new SetLabelPrimaryCmd(dfunc.address, dfunc.name.getName(), dfunc.namespace);
			cmd.applyTo(currentProgram);

			setExternalEntryPoint(dfunc.isExternal, dfunc.address);

			Function function = currentProgram.getListing().getFunctionAt(dfunc.address);
			if (function == null) {

				// TODO: If not contained within program memory should they be considered external?

				if (!currentProgram.getMemory()
						.getLoadedAndInitializedAddressSet()
						.contains(dfunc.address)) {
					Msg.warn(this,
						String.format(
							"DWARF: unable to create function not contained within loaded memory: %s@%s",
							dfunc.name, dfunc.address));
					return null;
				}

				// create 1-byte function if one does not exist - primary label will become function names
				function = currentProgram.getFunctionManager()
						.createFunction(null, dfunc.address, new AddressSet(dfunc.address),
							SourceType.IMPORTED);
			}

			return function;
		}
		catch (OverlappingFunctionException e) {
			throw new AssertException(e);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Failed to create function " + dfunc.namespace + "/" +
				dfunc.name.getName() + ": " + e.getMessage());
		}
		return null;
	}

	private void processLabel(DIEAggregate diea) {
		if (!shouldProcess(diea)) {
			return;
		}

		String name = prog.getEntryName(diea);
		if (name != null && diea.hasAttribute(DW_AT_low_pc)) {
			Address address = prog.getCodeAddress(diea.getLowPC(0));
			if (address.getOffset() != 0) {
				try {
					SymbolTable symbolTable = currentProgram.getSymbolTable();
					symbolTable.createLabel(address, name, currentProgram.getGlobalNamespace(),
						SourceType.IMPORTED);

					String locationInfo = DWARFSourceInfo.getDescriptionStr(diea);
					if (locationInfo != null) {
						appendComment(address, CodeUnit.EOL_COMMENT, locationInfo, "; ");
					}
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Problem creating label at " + address + " with name " + name,
						e);
				}
			}
		}
	}

}
