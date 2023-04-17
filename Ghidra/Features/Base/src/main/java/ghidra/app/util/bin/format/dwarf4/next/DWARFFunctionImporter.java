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
import java.util.stream.Collectors;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.expression.*;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Iterates through all DIEAs in a {@link DWARFProgram} and creates Ghidra functions
 * and variables.
 */
public class DWARFFunctionImporter extends DWARFVariableVisitor {

	/**
	 * Inline funcs shorter than this value receive comments at EOL instead of PRE
	 * (ie. inline funcs that reduce down to a single operand or operand value)
	 */
	private static final int INLINE_FUNC_SHORT_LEN = 8;

	private final DWARFImportOptions importOptions;

	private Map<Address, String> functionsProcessed = new HashMap<>();
	private TaskMonitor monitor;

	public static boolean hasDWARFProgModule(Program prog, String progModuleName) {
		ProgramModule dwarfModule = prog.getListing().getRootModule(progModuleName);

		return dwarfModule != null;
	}

	public DWARFFunctionImporter(DWARFProgram prog, DWARFDataTypeManager dwarfDTM,
			DWARFImportOptions importOptions, DWARFImportSummary importSummary,
			TaskMonitor monitor) {
		super(prog, prog.getGhidraProgram(), dwarfDTM);
		this.monitor = monitor;
		this.importOptions = importOptions;
		this.importSummary = importSummary;
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

		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog,
			"DWARF - Create Funcs & Symbols", monitor)) {
			monitor.checkCanceled();

			try {
				switch (diea.getTag()) {
					case DW_TAG_subprogram:
						try {
							processSubprogram(diea);
						}
						catch (InvalidInputException e) {
							Msg.error(this, "Failed to process subprog " + diea.getHexOffset(), e);
						}
						break;
					case DW_TAG_variable:
						// only process variable definitions that are static variables
						// (ie. they are children of the compunit root, ie. depth == 1)
						// local variables should be children of dw_tag_subprograms
						// and will be handled in processFuncChildren()
						if (diea.getDepth() == 1) {
							try {
								processVariable(diea, null, null, -1);
							}
							catch (InvalidInputException e) {
								Msg.error(this, "Failed to process var " + diea.getHexOffset(), e);
							}
						}
						break;
					case DW_TAG_label:
						processLabel(diea);
						break;

					case DW_TAG_gnu_call_site:
					case DW_TAG_call_site:
						DIEAggregate partDIEA = DIEAggregate.createSkipHead(diea);
						if (partDIEA != null && !isBadSubprogramDef(partDIEA)) {
							processSubprogram(partDIEA);
						}
						break;
				}
			}
			catch (OutOfMemoryError oom) {
				throw oom;
			}
			catch (Throwable th) {
				Msg.error(this,
					"Error when processing DWARF information for DIE " + diea.getHexOffset(), th);
				Msg.info(this, "DIE info:\n" + diea.toString());
			}
		}
		logImportErrorSummary();
	}

	private void logImportErrorSummary() {
		if (!importSummary.unknownRegistersEncountered.isEmpty()) {
			Msg.error(this, "Found " + importSummary.unknownRegistersEncountered.size() +
				" unknown registers referenced in DWARF expression operands:");
			List<Integer> sortedUnknownRegs =
				new ArrayList<>(importSummary.unknownRegistersEncountered);
			Collections.sort(sortedUnknownRegs);
			Msg.error(this,
				"  unknown registers: " +
					sortedUnknownRegs.stream().map(i -> Integer.toString(i)).collect(
						Collectors.joining(", ")));
		}
	}

	private boolean isBadSubprogramDef(DIEAggregate diea) {
		if (diea.isDanglingDeclaration() || !diea.hasAttribute(DWARFAttribute.DW_AT_low_pc)) {
			return true;
		}

		long lowPC = diea.getLowPC(0); // adjusted by program base addr fixup
		DWARFNumericAttribute attr =
			diea.getAttribute(DWARFAttribute.DW_AT_low_pc, DWARFNumericAttribute.class);
		if (attr != null && attr.getUnsignedValue() == 0 && lowPC != 0) {
			// don't process this func if its raw lowpc is 0, with the exception of a binary (a .o) 
			// that starts at 0 and has a function at 0
			return true;
		}

		return false;
	}

	private void markAllChildrenAsProcessed(DebugInfoEntry die) {
		for (DebugInfoEntry child : die.getChildren()) {
			processedOffsets.add(child.getOffset());
			markAllChildrenAsProcessed(child);
		}
	}

	
	
	
	private void processSubprogram(DIEAggregate diea)
			throws IOException, InvalidInputException, DWARFExpressionException {

		if (!shouldProcess(diea)) {
			return;
		}

		if (isBadSubprogramDef(diea)) {
			markAllChildrenAsProcessed(diea.getHeadFragment());
			return;
		}

		var dfunc = this.populateDWARFFunc(diea);
		String previousFunctionProcessed = functionsProcessed.get(dfunc.address);
		if (previousFunctionProcessed != null) {
//			Msg.info(this, "Duplicate function defintion found for " + dni.getCategoryPath() +
//				" at " + function.address + " in DIE " + diea.getHexOffset() + ", skipping");
			markAllChildrenAsProcessed(diea.getHeadFragment());
			return;
		}
		functionsProcessed.put(dfunc.address,
			dfunc.dni.getNamespacePath() + " DIE: " + diea.getHexOffset());

		// Check if the function is an external function
		dfunc.isExternal = diea.getBool(DWARFAttribute.DW_AT_external, false);

		// Retrieve the frame base if it exists
		DWARFLocation frameLoc = null;
		if (diea.hasAttribute(DWARFAttribute.DW_AT_frame_base)) {
			List<DWARFLocation> frameBase = diea.getAsLocation(DWARFAttribute.DW_AT_frame_base);
			// get the framebase register, find where the frame is finally set
			// up.
			frameLoc = getTopLocation(frameBase, dfunc.address.getOffset());
			if (frameLoc != null) {
				dfunc.frameBase = (int) diea.evaluateLocation(frameLoc);
			}
		}

		// Get it's return type
		// TODO: Sometimes the return type may actually be a pointer parameter
		// passed into
		// the given function - figure out how to determine this. For example,
		// C++ can
		// return object types defined in the function but may be implemented as
		// the caller
		// function passing a pointer to the callee function where the object is
		// then operated on.
		DIEAggregate typeRef = diea.getTypeRef();
		DataType formalReturnType = (typeRef != null)
				? dwarfDTM.getDataType(typeRef, DataType.DEFAULT)
				: dwarfDTM.getVoidType();
		dfunc.retval = new DWARFVariable();
		dfunc.retval.type = formalReturnType;

		boolean formalParamsOnly = false;
		boolean skipFuncSignature = false;
		List<Parameter> formalParams = new ArrayList<>();

		for (DIEAggregate paramDIEA : diea.getFunctionParamList()) {

			DataType paramDT = dwarfDTM.getDataType(paramDIEA.getTypeRef(), null);
			if (paramDT == null || DataTypeComponent.usesZeroLengthComponent(paramDT)) {
				String paramName = paramDIEA.getString(DW_AT_name, "param" + formalParams.size());
				Msg.warn(this, "DWARF: zero-length function parameter " + paramName +
					":" + paramDT.getName() + ", omitting from definition of " +
					dfunc.dni.getName() + "@" + dfunc.address);
				// skip this parameter because its data type is a zero-width type that typically does
				// not generate code.  If this varies compiler-to-compiler, setting 
				// skipFuncSignature=true may be a better choice
				continue;
			}

			Parameter formalParam = createFormalParameter(paramDIEA);
			if (formalParam == null) {
				skipFuncSignature = true;
				break;
			}
			formalParams.add(formalParam);

			if (!formalParamsOnly) {
				DWARFVariable var = processVariable(paramDIEA, dfunc, null, -1);
				if (var == null) {
					// we had an error, can't rely on detailed param data, fallback to
					// formal params
					formalParamsOnly = true;
					dfunc.params.clear();
				}
				else {
					dfunc.params.add(var);
				}
			}
		}
		dfunc.varArg = !diea.getChildren(DW_TAG_unspecified_parameters).isEmpty();

		processFuncChildren(diea, dfunc);

		Function gfunc = createFunction(dfunc, diea);

		if (gfunc != null) {
			if (diea.getBool(DW_AT_noreturn, false)) {
				gfunc.setNoReturn(true);
			}
			if (formalParams.isEmpty() && dfunc.localVarErrors) {
				// if there were no defined parameters and we had problems decoding local variables,
				// don't force the method to have an empty param signature because there are other
				// issues afoot.
				skipFuncSignature = true;
			}
			else if (formalParams.isEmpty() && diea.getCompilationUnit()
					.getCompileUnit()
					.getLanguage() == DWARFSourceLanguage.DW_LANG_Rust) {
				// if there were no defined parameters and the language is Rust, don't force an
				// empty param signature. Rust language emit dwarf info without types (signatures)
				// when used without -g.
				skipFuncSignature = true;
			}

			if (skipFuncSignature) {
				Msg.error(this,
					"Failed to get function signature information, leaving undefined: " +
						gfunc.getName() + "@" + gfunc.getEntryPoint());
				Msg.debug(this, "DIE info: " + diea.toString());
				return;
			}

			if (formalParamsOnly) {
				updateFunctionSignatureWithFormalParams(gfunc, formalParams,
					formalReturnType, dfunc.varArg, diea);
			}
			else {
				updateFunctionSignatureWithDetailParams(gfunc, dfunc, diea);
			}
		}

	}
	
	private void updateFunctionSignatureWithFormalParams(Function gfunc, List<Parameter> params,
			DataType returnType, boolean varArgs, DIEAggregate diea) {
		try {
			String callingConventionName = null;
			ReturnParameterImpl returnVar = new ReturnParameterImpl(returnType, currentProgram);
			try {
				if (!params.isEmpty() && Function.THIS_PARAM_NAME.equals(params.get(0).getName())) {
					// this handles the common / simple case.  More nuanced cases where the param
					// didn't have the correct "this" name, but were marked with DW_AT_object_pointer
					// or DW_AT_artifical won't be handled by this.
					callingConventionName = GenericCallingConvention.thiscall.getDeclarationName();
				}

				gfunc.setVarArgs(varArgs);
				gfunc.updateFunction(callingConventionName, returnVar, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				// try again after adjusting param names
				setUniqueParameterNames(gfunc, params);
				gfunc.updateFunction(callingConventionName, returnVar, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
			}
		}
		catch (InvalidInputException | DuplicateNameException e) {
			Msg.error(this,
				"Error updating function " + gfunc.getName() + " with formal params at " +
					gfunc.getEntryPoint().toString() + ": " + e.getMessage());
			Msg.error(this, "DIE info: " + diea.toString());
		}
	}

	private void updateFunctionSignatureWithDetailParams(Function gfunc, DWARFFunction dfunc,
			DIEAggregate diea) {
		try {
			CompilerSpec compilerSpec = currentProgram.getCompilerSpec();
			PrototypeModel convention = null;
			Variable returnVariable;
			List<Parameter> params = new ArrayList<>();

			returnVariable = buildReturnVariable(dfunc.retval);
			for (int i = 0; i < dfunc.params.size(); ++i) {
				Parameter curparam = buildParameter(gfunc, i, dfunc.params.get(i), diea);
				params.add(curparam);
				if (i == 0 && checkThisParameter(dfunc.params.get(0), diea)) {
					convention = compilerSpec.matchConvention(GenericCallingConvention.thiscall);
				}
			}

			if (dfunc.retval != null || params.size() > 0) {
				// Add the function signature definition into the data type manager
// TODO:				createFunctionDefinition(dfunc, infopath);

				// NOTE: Storage is computed above for the purpose of identifying
				// a best fit calling convention.  The commitPrototype method currently
				// always employs dynamic storage.
				commitPrototype(gfunc, returnVariable, params, convention);
				gfunc.setVarArgs(dfunc.varArg);
			}
		}
		catch (InvalidInputException | DuplicateNameException iie) {
			Msg.error(this, "Error updating function " + dfunc.dni.getName() + " at " +
				dfunc.address.toString() + ": " + iie.getMessage());
		}
	}

	private void processFuncChildren(DIEAggregate diea, DWARFFunction dfunc)
			throws InvalidInputException, IOException, DWARFExpressionException {

		for (DebugInfoEntry childEntry : diea.getHeadFragment().getChildren()) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);

			switch (childDIEA.getTag()) {
				case DW_TAG_variable: {
					// We wait to add variables for when we have stack info
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
					if (partDIEA != null && !isBadSubprogramDef(partDIEA)) {
						processSubprogram(partDIEA);
					}
					break;

			}
		}
	}

	private Parameter createFormalParameter(DIEAggregate diea) {
		String name = diea.getString(DW_AT_name, null);
		DataType dt = dwarfDTM.getDataType(diea.getTypeRef(), dwarfDTM.getVoidType());

		try {
			return new ParameterImpl(name, dt, currentProgram);
		}
		catch (InvalidInputException e) {
			Msg.debug(this, "Failed to create parameter for " + diea.toString());
		}
		return null;
	}

	/**
	 * Process lexical block entries.
	 *
	 * @param entry
	 *            DIE
	 * @param unit
	 *            current compilation unit
	 * @param frameBase
	 *            Location list of the current frame
	 * @param function
	 *            parent function of the lexical block
	 * @throws IOException
	 * @throws InvalidInputException
	 * @throws DWARFExpressionException
	 */
	private void processLexicalBlock(DIEAggregate diea, DWARFFunction dfunc)
			throws IOException, InvalidInputException, DWARFExpressionException {
		if (!shouldProcess(diea)) {
			return;
		}

		DWARFNameInfo dni = prog.getName(diea);

		String name = dni.getName();
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
			List<DWARFRange> ranges = diea.parseDebugRange(DWARFAttribute.DW_AT_ranges);

			// No range found
			if (ranges.isEmpty()) {
				return;
			}

			lowPC = ranges.get(0).getFrom();
			disjoint = ranges.size() > 1;
		}
		else {
			Msg.error(this, "LEXICAL BLOCK: No start and end ranges were found so the lexical " +
				"block could not be processed.");
			return;
		}
		Address blockStart = toAddr(lowPC);
		if (name != null && importOptions.isOutputLexicalBlockComments()) {
			appendComment(blockStart, CodeUnit.PRE_COMMENT,
				"Begin: " + name + (disjoint ? " - Disjoint" : ""), "\n");
		}

		processFuncChildren(diea, dfunc);
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

		if (importOptions.isOutputInlineFuncComments()) {
			addCommentsForInlineFunc(diea, toAddr(lowPC), toAddr(highPC));
		}

		processFuncChildren(diea, dfunc);
	}

	/**
	 * Constructs a function def signature for the function and adds it as a comment, either
	 * EOL or PRE depending on how small the inline func is.
	 * @param diea
	 * @param blockStart
	 * @param blockEnd
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

	private Variable buildReturnVariable(DWARFVariable dvar) throws InvalidInputException {
		if (dvar == null) {
			return new ReturnParameterImpl(DataType.VOID, currentProgram);
		}
		VariableStorage storage;
		Varnode[] vnarray = buildVarnodes(dvar);
		if (vnarray == null) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		else {
			storage = new VariableStorage(currentProgram, vnarray);
		}
		return new ReturnParameterImpl(dvar.type, storage, currentProgram);
	}

	private Parameter buildParameter(Function function, int i, DWARFVariable dvar,
			DIEAggregate funcDIEA) throws InvalidInputException {
		VariableStorage storage;
		Varnode[] vnarray = buildVarnodes(dvar);
		if (vnarray == null) {
			storage = VariableStorage.UNASSIGNED_STORAGE;
		}
		else {
			storage = new VariableStorage(currentProgram, vnarray);
		}

		return new ParameterImpl(dvar.dni.getName(), dvar.type, storage, currentProgram);
	}

	private boolean checkThisParameter(DWARFVariable var, DIEAggregate diea) {
		// If the variable is not named, check to see if the datatype is the same
		// as the parent entry
		if (Function.THIS_PARAM_NAME.equals(var.dni.getName())) {
			return true;
		}

		// Check for a parent class
		DIEAggregate parentDIEA = diea.getParent();
		if (parentDIEA != null && parentDIEA.isStructureType()) {
			DataType parentDT = dwarfDTM.getDataType(parentDIEA, null);
			// Check to see if the parent data type equals the parameters' data type
			if (parentDT != null && parentDT == var.type) {
				if (!var.dni.isAnon()) {
					Msg.error(this, "WARNING: Renaming " + var.dni.getName() + " to " +
						Function.THIS_PARAM_NAME);
				}
				var.dni = var.dni.replaceName(Function.THIS_PARAM_NAME, Function.THIS_PARAM_NAME);
				return true;
			}
		}
		return false;
	}

	private Function createFunction(DWARFFunction dfunc, DIEAggregate diea) {
		try {
			// create a new symbol if one does not exist (symbol table will figure this out)
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			symbolTable.createLabel(dfunc.address, dfunc.dni.getName(), dfunc.namespace,
				SourceType.IMPORTED);

			// force new label to become primary (if already a function it will become function name)
			SetLabelPrimaryCmd cmd =
				new SetLabelPrimaryCmd(dfunc.address, dfunc.dni.getName(), dfunc.namespace);
			cmd.applyTo(currentProgram);

			setExternalEntryPoint(dfunc.isExternal, dfunc.address);

			Function function = currentProgram.getListing().getFunctionAt(dfunc.address);
			if (function == null) {

				// TODO: If not contained within program memory should they be considered external?

				if (!currentProgram.getMemory().getLoadedAndInitializedAddressSet().contains(
					dfunc.address)) {
					Msg.warn(this,
						"Unable to create function not contained within loaded memory (" +
							dfunc.address + ") " + dfunc.namespace + "/" + dfunc.dni.getName());
					return null;
				}

				// create 1-byte function if one does not exist - primary label will become function names
				function = currentProgram.getFunctionManager().createFunction(null, dfunc.address,
					new AddressSet(dfunc.address), SourceType.IMPORTED);
			}

			DWARFSourceInfo sourceInfo = DWARFSourceInfo.create(diea);
			if (sourceInfo != null) {
				// Move the function into the program tree of the file
				moveIntoFragment(function.getName(), dfunc.address,
					dfunc.highAddress != null ? dfunc.highAddress : dfunc.address.add(1),
					sourceInfo.getFilename());

				if (importOptions.isOutputSourceLocationInfo()) {
					appendComment(dfunc.address, CodeUnit.PLATE_COMMENT,
						sourceInfo.getDescriptionStr(), "\n");
				}
			}
			if (importOptions.isOutputDIEInfo()) {
				appendComment(dfunc.address, CodeUnit.PLATE_COMMENT,
					"DWARF DIE: " + diea.getHexOffset(), "\n");
			}

			DWARFNameInfo dni = prog.getName(diea);
			if (dni.isNameModified()) {
				appendComment(dfunc.address, CodeUnit.PLATE_COMMENT,
					"Original name: " + dni.getOriginalName(), "\n");
			}

			return function;
		}
		catch (OverlappingFunctionException e) {
			throw new AssertException(e);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Failed to create function " + dfunc.namespace + "/" +
				dfunc.dni.getName() + ": " + e.getMessage());
		}
		return null;
	}

	/**
	 * Changes the names of the parameters in the array to unique names that won't conflict with
	 * any other names in the function's namespace when the parameters are used to replace
	 * the existing parameters in the function. Appends an integer number to
	 * the base name if necessary to create a unique name in the function's namespace.
	 * @param function the function
	 * @param parameters the parameters that need names that won't conflict. These should be
	 * Impl objects and not DB objects since their names will be changed within this method.
	 * @throws InvalidInputException invalid parameter name
	 * @throws DuplicateNameException (should not occur on non-DB parameter)
	 */
	private void setUniqueParameterNames(Function function, List<Parameter> parameters)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		// Create a set containing all the unique parameter names determined so far so they can
		// be avoided as additional parameter names are determined.
		Set<String> namesSoFar = new HashSet<>();
		for (int ordinal = 0; ordinal < parameters.size(); ordinal++) {
			Parameter parameter = parameters.get(ordinal);
			String baseName = parameter.getName();
			if (ordinal == 0 && Function.THIS_PARAM_NAME.equals(baseName)) {
				continue;
			}
			String uniqueName =
				getUniqueReplacementParameterName(symbolTable, function, baseName, namesSoFar);
			namesSoFar.add(uniqueName);
			parameter.setName(uniqueName, SourceType.IMPORTED);
		}
	}

	/**
	 * Get a unique parameter name for a parameter when all parameter names are being replaced.
	 * If the specified name is  a default parameter name then the original default name passed
	 * in is returned.
	 * @param symbolTable the symbol table containing symbols for the indicated namespace
	 * @param namespace the namespace containing symbol names to check.
	 * @param baseName the base name to append with an integer number if necessary
	 * to create a unique name.
	 * @param namesNotToBeUsed set of names that should not be used when determining a unique name.
	 * @return a unique parameter name
	 */
	private static String getUniqueReplacementParameterName(SymbolTable symbolTable,
			Function function, String name, Set<String> namesNotToBeUsed) {
		if (name == null || SymbolUtilities.isDefaultParameterName(name)) {
			return name;
		}
		return getUniqueNameIgnoringCurrentParameters(symbolTable, function, name,
			namesNotToBeUsed);
	}

	/**
	 * Gets a unique name in the indicated namespace by appending an integer number if necessary
	 * and ignoring any conflicts with existing parameters.
	 * @param symbolTable the symbol table containing symbols for the indicated namespace
	 * @param namespace the namespace containing symbol names to check.
	 * @param baseName the base name to append with an integer number if necessary to create a
	 * unique name.
	 * @param namesNotToBeUsed set of names that should not be used when determining a unique name.
	 * @return an unused unique name within the namespace ignoring current parameter names and
	 * that doesn't conflict with any in the set of names not to be used.
	 */
	private static String getUniqueNameIgnoringCurrentParameters(SymbolTable symbolTable,
			Namespace namespace, String baseName, Set<String> namesNotToBeUsed) {
		String name = baseName;
		if (name != null) {
			// establish unique name
			int cnt = 0;
			List<Symbol> symbols = symbolTable.getSymbols(name, namespace);
			while (!symbols.isEmpty()) {
				if (namesNotToBeUsed.contains(name)) {
					continue;
				}
				if (areAllParamaters(symbols)) {
					return name;
				}
				name = baseName + "_" + (++cnt);
				symbols = symbolTable.getSymbols(name, namespace);
			}
		}
		return name;
	}

	private static boolean areAllParamaters(List<Symbol> symbols) {
		for (Symbol symbol : symbols) {
			if (symbol.getSymbolType() != SymbolType.PARAMETER) {
				return false;
			}
		}
		return true;
	}

	private void commitPrototype(Function function, Variable returnVariable,
			List<Parameter> params, PrototypeModel protoModel)
			throws InvalidInputException, DuplicateNameException {

		CompilerSpec compilerSpec = currentProgram.getCompilerSpec();

		if (protoModel == null) {
			Parameter[] paramarray = params.toArray(Parameter[]::new);
			protoModel = compilerSpec.findBestCallingConvention(paramarray);
		}

		try {
			function.updateFunction(protoModel.getName(), returnVariable, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
		}
		catch (DuplicateNameException e) {
			setUniqueParameterNames(function, params);
			function.updateFunction(protoModel.getName(), returnVariable, params,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
		}

// TODO: Determination of storage is unreliable and frequently forces incorrect storage to be used
//		if (useCustomStorageIfNeeded &&
//			!VariableUtilities.storageMatches(params, function.getParameters())) {
//			// try again if dynamic storage assignment does not match what DWARF specified
//			// force into custom storage mode
//			function.updateFunction(protoModel.getName(), null, params,
//				FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
//		}
	}


	private void processLabel(DIEAggregate diea) {
		if (!shouldProcess(diea)) {
			return;
		}

		String name = prog.getEntryName(diea);
		if (name != null && diea.hasAttribute(DW_AT_low_pc)) {
			Address address = toAddr(diea.getLowPC(0));
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

	/**
	 * Holds values necessary to create a new function
	 */
	static class DWARFFunction {
		public Address address;
		public Address highAddress;
		public DWARFNameInfo dni;
		public Namespace namespace;
		public DWARFVariable retval;
		public boolean isExternal;
		public long frameBase;
		public List<DWARFVariable> params = new ArrayList<>();
		public List<DWARFVariable> local = new ArrayList<>();
		public boolean varArg;
		public boolean localVarErrors;	// set to true if problem w/local var decoding

		public DWARFFunction(DWARFNameInfo dni) {
			this.dni = dni;
		}
	}

	@Override
	protected Optional<Long> resolveStackOffset(long off, DWARFLocation loc, DWARFFunction dfunc, boolean validRange, Optional<Address> block_start) {
		return Optional.empty();
	}
}
