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

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.*;
import ghidra.app.util.bin.format.dwarf4.expression.*;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.Varnode;
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

	private ProgramModule rootModule;// Program tree module for DWARF
	private Set<Long> processedOffsets = new HashSet<>();
	private Map<Address, String> functionsProcessed = new HashMap<>();
	private Set<Address> variablesProcesesed = new HashSet<>();

	private TaskMonitor monitor;

	private DWARFImportSummary importSummary;

	public static boolean hasDWARFProgModule(Program prog, String progModuleName) {
		ProgramModule dwarfModule = prog.getListing().getRootModule(progModuleName);

		return dwarfModule != null;
	}

	public DWARFFunctionImporter(DWARFProgram prog, DWARFDataTypeManager dwarfDTM,
			DWARFImportOptions importOptions, DWARFImportSummary importSummary,
			TaskMonitor monitor) {
		this.prog = prog;
		this.monitor = monitor;
		this.currentProgram = prog.getGhidraProgram();
		this.dwarfDTM = dwarfDTM;
		this.importOptions = importOptions;
		this.importSummary = importSummary;
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

		for (DIEAggregate diea : DIEAMonitoredIterator.iterable(prog,
			"DWARF - Create Funcs & Symbols", monitor)) {
			monitor.checkCanceled();

			try {
				switch (diea.getTag()) {
					case DWARFTag.DW_TAG_subprogram:
						try {
							processSubprogram(diea);
						}
						catch (InvalidInputException e) {
							Msg.error(this, "Failed to process subprog " + diea.getHexOffset(), e);
						}
						break;
					case DWARFTag.DW_TAG_variable:
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
					case DWARFTag.DW_TAG_label:
						processLabel(diea);
						break;

					case DWARFTag.DW_TAG_gnu_call_site:
					case DWARFTag.DW_TAG_call_site:
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

		if (diea.getLowPC(-1) == 0) {
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

		DWARFFunction dfunc = new DWARFFunction(prog.getName(diea));
		dfunc.namespace = dfunc.dni.getParentNamespace(currentProgram);

		Number lowPC = diea.getLowPC(0);
		dfunc.address = toAddr(lowPC);
		dfunc.highAddress =
			diea.hasAttribute(DWARFAttribute.DW_AT_high_pc) ? toAddr(diea.getHighPC()) : null;

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

		for (DebugInfoEntry childEntry : diea.getHeadFragment().getChildren(
			DWARFTag.DW_TAG_formal_parameter)) {
			DIEAggregate childDIEA = prog.getAggregate(childEntry);

			DataType childDT = dwarfDTM.getDataType(childDIEA.getTypeRef(), null);
			if (childDT == null || DataTypeComponent.usesZeroLengthComponent(childDT)) {
				String paramName =
					childDIEA.getString(DWARFAttribute.DW_AT_name, "param" + formalParams.size());
				Msg.warn(this, "DWARF: zero-length function parameter " + paramName +
					":" + childDT.getName() + ", omitting from definition of " +
					dfunc.dni.getName() + "@" + dfunc.address);
				// skip this parameter because its data type is a zero-width type that typically does
				// not generate code.  If this varies compiler-to-compiler, setting 
				// skipFuncSignature=true may be a better choice
				continue;
			}

			Parameter formalParam = createFormalParameter(childDIEA);
			if (formalParam == null) {
				skipFuncSignature = true;
				break;
			}
			formalParams.add(formalParam);

			if (!formalParamsOnly) {
				DWARFVariable var = processVariable(childDIEA, dfunc, null, -1);
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
		dfunc.varArg =
			!diea.getHeadFragment().getChildren(DWARFTag.DW_TAG_unspecified_parameters).isEmpty();

		processFuncChildren(diea, dfunc);

		Function gfunc = createFunction(dfunc, diea);

		if (gfunc != null) {
			if (diea.getBool(DWARFAttribute.DW_AT_noreturn, false)) {
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
			ReturnParameterImpl returnVar = new ReturnParameterImpl(returnType, currentProgram);
			try {
				gfunc.setVarArgs(varArgs);
				gfunc.updateFunction(null, returnVar, params,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				// try again after adjusting param names
				setUniqueParameterNames(gfunc, params);
				gfunc.updateFunction(null, returnVar, params,
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

			for (int i = 0; i < dfunc.local.size(); ++i) {
				commitLocal(gfunc, dfunc.local.get(i));
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
				case DWARFTag.DW_TAG_variable: {
					DWARFVariable var =
						processVariable(childDIEA, dfunc, null, dfunc.address.getOffset());

					if ((var != null) && var.isStackOffset) {
						dfunc.local.add(var);
					}
					break;
				}
				case DWARFTag.DW_TAG_lexical_block:
					processLexicalBlock(childDIEA, dfunc);
					break;
				case DWARFTag.DW_TAG_label:
					processLabel(childDIEA);
					break;
				case DWARFTag.DW_TAG_inlined_subroutine:
					processInlinedSubroutine(childDIEA, dfunc);
					break;

				case DWARFTag.DW_TAG_gnu_call_site:
				case DWARFTag.DW_TAG_call_site:
					DIEAggregate partDIEA = DIEAggregate.createSkipHead(diea);
					if (partDIEA != null && !isBadSubprogramDef(partDIEA)) {
						processSubprogram(partDIEA);
					}
					break;

			}
		}
	}

	private Parameter createFormalParameter(DIEAggregate diea) {
		String name = diea.getString(DWARFAttribute.DW_AT_name, null);
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
	 * Creates a new {@link DWARFVariable} from the specified {@link DIEAggregate DIEA} and
	 * as a child of the specified function (if not null).
	 * <p>
	 * Used to process DW_TAG_variable as well as DW_TAG_formal_parameters.
	 *
	 * @param diea - the diea that specifies the variable
	 * @param dfunc - function that contains this variable, or null if static variable
	 * @param lexicalStart - not used by any caller
	 * @param firstUseAddr offset dfunc or -1 if formal parameter
	 * @return
	 * @throws IOException
	 * @throws InvalidInputException
	 */
	private DWARFVariable processVariable(DIEAggregate diea, DWARFFunction dfunc,
			Address lexicalStart, long firstUseAddr) throws IOException, InvalidInputException {

		if (!shouldProcess(diea)) {
			return null;
		}

		long funcAddr = (dfunc != null && dfunc.address != null) ? dfunc.address.getOffset() : -1;

		DWARFVariable dvar = new DWARFVariable();
		dvar.dni = prog.getName(diea);
		dvar.lexicalOffset = dfunc != null && dfunc.address != null && lexicalStart != null
				? lexicalStart.subtract(dfunc.address)
				: -1;

		// Unknown variable location
		if (!diea.hasAttribute(DWARFAttribute.DW_AT_location)) {
			return null;
		}

		List<DWARFLocation> locList = diea.getAsLocation(DWARFAttribute.DW_AT_location);

		// If we are trying to recover a local variable, only process the
		// variable if it has a single location over the entire function
		if ((firstUseAddr != -1) && locList.size() > 1) {
			return null;
		}

		DWARFLocation topLocation = getTopLocation(locList, funcAddr);
		if (topLocation == null) {
			if (dfunc != null) {
				dfunc.localVarErrors = true;
			}
			return null;
		}

		// Get the base type of this variable
		dvar.type = dwarfDTM.getDataType(diea.getTypeRef(), dwarfDTM.getVoidType());

		long frameBase = (dfunc != null) ? dfunc.frameBase : -1;
		DWARFExpressionEvaluator exprEvaluator =
			DWARFExpressionEvaluator.create(diea.getHeadFragment());
		exprEvaluator.setFrameBase(frameBase);
		long res;
		try {
			DWARFExpression expr = exprEvaluator.readExpr(topLocation.getLocation());
			exprEvaluator.evaluate(expr);
			res = exprEvaluator.pop();
		}
		catch (DWARFExpressionException | UnsupportedOperationException
				| IndexOutOfBoundsException ex) {
			importSummary.exprReadError++;
			if (dfunc != null) {
				dfunc.localVarErrors = true;
			}

			return null;
		}

		if (exprEvaluator.isDwarfStackValue()) {
			importSummary.varDWARFExpressionValue++;
			if (dfunc != null) {
				dfunc.localVarErrors = true;
			}
			return null;
		}
		else if (exprEvaluator.useUnknownRegister() && exprEvaluator.isRegisterLocation()) {
			dvar.reg = exprEvaluator.getLastRegister();
			dvar.type = dwarfDTM.getPtrTo(dvar.type);

			// TODO: fix this later.  Lie and use lexicalOffset-1 so the GUI correctly shows the first use
			dvar.offset = dvar.lexicalOffset != -1 ? dvar.lexicalOffset - 1 : -1;
			return dvar;
		}
		else if (exprEvaluator.useUnknownRegister()) {
			importSummary.varDynamicRegisterError++;
			if (dfunc != null) {
				dfunc.localVarErrors = true;
			}
			return null;
		}
		else if (exprEvaluator.isStackRelative()) {
			dvar.offset = res;
			dvar.reg = null;
			dvar.isStackOffset = true;
			if (exprEvaluator.isDeref()) {
				dvar.type = dwarfDTM.getPtrTo(dvar.type);
			}
		}
		else if (exprEvaluator.isRegisterLocation()) {
			// The DWARF expression evaluated to a simple register.  If we have a mapping
			// for it in the "processor.dwarf" register mapping file, try to create
			// a variable, otherwise log the unknown register for later logging.
			dvar.reg = exprEvaluator.getLastRegister();
			if (dvar.reg != null) {
				dvar.offset = -1;
				if (firstUseAddr != -1) {
					dvar.offset = findFirstUse(currentProgram, dvar.reg, funcAddr, firstUseAddr);
				}
				if ((dvar.type != null) &&
					(dvar.type.getLength() > dvar.reg.getMinimumByteSize())) {
					importSummary.varFitError++;

					String contextStr = (dfunc != null)
							? " for function " + dfunc.dni.getName() + "@" + dfunc.address
							: "";
					if (diea.getTag() != DWARFTag.DW_TAG_formal_parameter) {
						Msg.warn(this,
							"Variable " + dvar.dni.getName() + "[" + dvar.type.getName() +
								", size=" + dvar.type.getLength() + "]" + contextStr +
								" can not fit into specified register " + dvar.reg.getName() +
								", size=" + dvar.reg.getMinimumByteSize() +
								", skipping.  DWARF DIE: " + diea.getHexOffset());
						if (dfunc != null) {
							dfunc.localVarErrors = true;
						}
						return null;
					}

					dvar.type = dwarfDTM.getUndefined1Type();
				}
			}
			else {
				// The DWARF register did not have a mapping to a Ghidra register, so
				// log it to be displayed in an error summary at end of import phase.
				importSummary.unknownRegistersEncountered.add(exprEvaluator.getRawLastRegister());
				if (dfunc != null) {
					dfunc.localVarErrors = true;
				}
				return null;
			}
		}
		else if (exprEvaluator.getLastRegister() == null) {
			processStaticVar(res, dvar, diea);
			return null;// Don't return the variable to be associated with the function
		}
		else {
			Msg.error(this,
				"LOCAL VAR: " + dvar.dni.getName() + " : " +
					ghidra.app.util.bin.format.dwarf4.expression.DWARFExpression.exprToString(
						topLocation.getLocation(), diea) +
					", DWARF DIE: " + diea.getHexOffset());
			return null;
		}
		return dvar;
	}

	private void processStaticVar(long address, DWARFVariable dvar, DIEAggregate diea)
			throws InvalidInputException {
		dvar.dni = dvar.dni.replaceType(null /*nothing matches static global var*/);
		if (address != 0) {
			Address staticVariableAddress = toAddr(address + prog.getProgramBaseAddressFixup());
			if (isZeroByteDataType(dvar.type)) {
				processZeroByteStaticVar(staticVariableAddress, dvar);
				return;
			}

			if (variablesProcesesed.contains(staticVariableAddress)) {
				return;
			}

			boolean external = diea.getBool(DWARFAttribute.DW_AT_external, false);

			outputGlobal(staticVariableAddress, dvar.type, external,
				DWARFSourceInfo.create(diea), dvar.dni);
		}
		else {
			// If the expression evaluated to a static address of '0'.
			// This case is probably caused by relocation fixups not being applied to the
			// .debug_info section.
			importSummary.relocationErrorVarDefs.add(
				dvar.dni.getNamespacePath().asFormattedString() + " : " +
					dvar.type.getPathName());
		}
	}

	private void processZeroByteStaticVar(Address staticVariableAddress, DWARFVariable dvar)
			throws InvalidInputException {
		// because this is a zero-length data type (ie. array[0]),
		// don't create a variable at the location since it will prevent other elements
		// from occupying the same offset
		Listing listing = currentProgram.getListing();
		String comment =
			listing.getComment(CodeUnit.PRE_COMMENT, staticVariableAddress);
		comment = (comment != null) ? comment + "\n" : "";
		comment += String.format("Zero length variable: %s: %s", dvar.dni.getOriginalName(),
			dvar.type.getDisplayName());
		listing.setComment(staticVariableAddress, CodeUnit.PRE_COMMENT, comment);

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		symbolTable.createLabel(staticVariableAddress, dvar.dni.getName(),
			dvar.dni.getParentNamespace(currentProgram),
			SourceType.IMPORTED);
	}

	private boolean isZeroByteDataType(DataType dt) {
		if (!dt.isZeroLength() && dt instanceof Array) {
			dt = DataTypeUtilities.getArrayBaseDataType((Array) dt);
		}
		return dt.isZeroLength();
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
		if (diea.hasAttribute(DWARFAttribute.DW_AT_low_pc) &&
			diea.hasAttribute(DWARFAttribute.DW_AT_high_pc)) {
			lowPC = diea.getLowPC(0);
		}
		// Otherwise process a range list
		else if (diea.hasAttribute(DWARFAttribute.DW_AT_ranges)) {
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
		if (diea.hasAttribute(DWARFAttribute.DW_AT_low_pc) &&
			diea.hasAttribute(DWARFAttribute.DW_AT_high_pc)) {
			lowPC = diea.getLowPC(0);
			highPC = diea.getHighPC();
		}
		// Otherwise process a range list
		else if (diea.hasAttribute(DWARFAttribute.DW_AT_ranges)) {
			List<DWARFRange> ranges = diea.parseDebugRange(DWARFAttribute.DW_AT_ranges);

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

	/**
	 * Appends a comment at the specified address
	 * @param address the address to set the PRE comment
	 * @param commentType ie. CodeUnit.PRE_COMMENT
	 * @param comment the PRE comment
	 * @param sep the characters to use to separate existing comments
	 * @return true if the comment was successfully set
	 */
	private boolean appendComment(Address address, int commentType, String comment, String sep) {
		AppendCommentCmd cmd = new AppendCommentCmd(address, commentType, comment, sep);
		return cmd.applyTo(currentProgram);
	}

	private final Address toAddr(Number offset) {
		return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(
			offset.longValue(), true);
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

	private boolean isArrayDataTypeCompatibleWithExistingData(Array arrayDT, Address address) {
		Listing listing = currentProgram.getListing();

		// quick success
		Data arrayData = listing.getDataAt(address);
		if (arrayData != null && arrayData.getBaseDataType().isEquivalent(arrayDT)) {
			return true;
		}

		if (arrayData != null && arrayDT.getDataType() instanceof CharDataType &&
			arrayData.getBaseDataType() instanceof StringDataType) {
			if (arrayData.getLength() >= arrayDT.getLength()) {
				return true;
			}
			return DataUtilities.isUndefinedRange(currentProgram,
				address.add(arrayData.getLength()), address.add(arrayDT.getLength() - 1));
		}

		// test each element
		for (int i = 0; i < arrayDT.getNumElements(); i++) {
			Address elementAddress = address.add(arrayDT.getElementLength() * i);
			Data data = listing.getDataAt(elementAddress);
			if (data != null &&
				!isDataTypeCompatibleWithExistingData(arrayDT.getDataType(), elementAddress)) {
				return false;
			}
		}

		return true;
	}

	private boolean isStructDataTypeCompatibleWithExistingData(Structure structDT,
			Address address) {
		for (DataTypeComponent dtc : structDT.getDefinedComponents()) {
			Address memberAddress = address.add(dtc.getOffset());
			if (!isDataTypeCompatibleWithExistingData(dtc.getDataType(), memberAddress)) {
				return false;
			}
		}
		return true;
	}

	private boolean isPointerDataTypeCompatibleWithExistingData(Pointer pdt, Address address) {
		Listing listing = currentProgram.getListing();
		Data data = listing.getDataAt(address);
		if (data == null) {
			return true;
		}

		DataType dataDT = data.getBaseDataType();
		return dataDT instanceof Pointer;
	}

	private boolean isSimpleDataTypeCompatibleWithExistingData(DataType dataType, Address address) {
		Listing listing = currentProgram.getListing();

		Data data = listing.getDataAt(address);
		if (data == null) {
			return true;
		}

		DataType dataDT = data.getBaseDataType();
		if (dataType instanceof CharDataType && dataDT instanceof StringDataType) {
			return true;
		}

		if (!dataType.getClass().isInstance(dataDT)) {
			return false;
		}
		int dataTypeLen = dataType.getLength();
		if (dataTypeLen > 0 && dataTypeLen != data.getLength()) {
			return false;
		}
		return true;
	}

	private boolean isEnumDataTypeCompatibleWithExistingData(Enum enumDT, Address address) {
		Listing listing = currentProgram.getListing();
		Data data = listing.getDataAt(address);
		if (data == null) {
			return true;
		}

		DataType dataDT = data.getBaseDataType();
		if (!(dataDT instanceof Enum || dataDT instanceof AbstractIntegerDataType)) {
			return false;
		}
		if (dataDT instanceof BooleanDataType) {
			return false;
		}
		if (dataDT.getLength() != enumDT.getLength()) {
			return false;
		}
		return true;
	}

	private boolean isDataTypeCompatibleWithExistingData(DataType dataType, Address address) {
		if (DataUtilities.isUndefinedRange(currentProgram, address,
			address.add(dataType.getLength() - 1))) {
			return true;
		}

		if (dataType instanceof Array) {
			return isArrayDataTypeCompatibleWithExistingData((Array) dataType, address);
		}
		if (dataType instanceof Pointer) {
			return isPointerDataTypeCompatibleWithExistingData((Pointer) dataType, address);
		}
		if (dataType instanceof Structure) {
			return isStructDataTypeCompatibleWithExistingData((Structure) dataType, address);
		}
		if (dataType instanceof TypeDef) {
			return isDataTypeCompatibleWithExistingData(((TypeDef) dataType).getBaseDataType(),
				address);
		}
		if (dataType instanceof Enum) {
			return isEnumDataTypeCompatibleWithExistingData((Enum) dataType, address);
		}

		if (dataType instanceof CharDataType || dataType instanceof StringDataType ||
			dataType instanceof IntegerDataType || dataType instanceof UnsignedIntegerDataType ||
			dataType instanceof BooleanDataType) {
			return isSimpleDataTypeCompatibleWithExistingData(dataType, address);
		}

		return false;
	}

	private Data createVariable(Address address, DataType dataType, DWARFNameInfo dni) {
		try {
			String eolComment = null;
			if (dataType instanceof Dynamic || dataType instanceof FactoryDataType) {
				eolComment = "Unsupported dynamic data type: " + dataType;
				dataType = Undefined.getUndefinedDataType(1);
			}
			if (!isDataTypeCompatibleWithExistingData(dataType, address)) {
				appendComment(address, CodeUnit.EOL_COMMENT,
					"Could not place DWARF static variable " +
						dni.getNamespacePath().asFormattedString() + " : " + dataType +
						" because existing data type conflicts.",
					"\n");
				return null;
			}
			Data result = DataUtilities.createData(currentProgram, address, dataType, -1, false,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			variablesProcesesed.add(address);
			if (eolComment != null) {
				appendComment(address, CodeUnit.EOL_COMMENT, eolComment, "\n");
			}
			return result;
		}
		catch (CodeUnitInsertionException | DataTypeConflictException e) {
			Msg.error(this, "Error creating data object at " + address, e);
		}
		return null;
	}

	private void outputGlobal(Address address, DataType baseDataType, boolean external,
			DWARFSourceInfo sourceInfo, DWARFNameInfo dni) {

		Namespace namespace = dni.getParentNamespace(currentProgram);

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		try {
			symbolTable.createLabel(address, dni.getName(), namespace, SourceType.IMPORTED);
			SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, dni.getName(), namespace);
			cmd.applyTo(currentProgram);
		}
		catch (InvalidInputException e) {
			Msg.error(this,
				"Error creating symbol " + namespace + "/" + dni.getName() + " at " + address);
			return;
		}

		setExternalEntryPoint(external, address);

		Data varData = createVariable(address, baseDataType, dni);
		importSummary.globalVarsAdded++;

		if (sourceInfo != null) {
			appendComment(address, CodeUnit.EOL_COMMENT, sourceInfo.getDescriptionStr(), "\n");

			if (varData != null) {
				moveIntoFragment(dni.getName(), varData.getMinAddress(), varData.getMaxAddress(),
					sourceInfo.getFilename());
			}
		}
	}

	/**
	 * Get the location that corresponds to the entry point of the function If
	 * there is only a single location, assume it applies to whole function
	 *
	 * @param locList
	 * @param funcAddr
	 * @return the byte array corresponding to the location expression
	 */
	private static DWARFLocation getTopLocation(List<DWARFLocation> locList, long funcAddr) {
		if (locList.size() == 1) {
			return locList.get(0);
		}
		for (DWARFLocation loc : locList) {
			if (loc.getRange().getFrom() == funcAddr) {
				return loc;
			}
		}
		return null;
	}

	private static int findFirstUse(Program currentProgram, Register register, long funcAddr,
			long firstUseAddr) {
		// look for the first write to this register within this range.
		Address entry = currentProgram.getMinAddress().getNewAddress(firstUseAddr);
		InstructionIterator instructions = currentProgram.getListing().getInstructions(entry, true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();

			FlowType flowType = instruction.getFlowType();
			if (flowType.isTerminal()) {
				return 0;
			}
			Object[] resultObjects = instruction.getResultObjects();
			for (int i = 0; i < resultObjects.length; i++) {
				if (!(resultObjects[i] instanceof Register)) {
					continue;
				}
				Register outReg = (Register) resultObjects[i];
				if (register.equals(outReg)) {
					long offset = instruction.getMinAddress().getOffset() - funcAddr;
					return (int) offset;
				}
			}
		}
		// return the offset from the function entry to the real first use
		return 0;
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

	/**
	 * For some DWARF debugger strategies, the storage location provided for a formal parameter is NOT the initial storage
	 * of the parameter and does not match the calling convention.  If the storage location provided is in the local variable
	 * range for the function, this is an indication the storage does not represent the calling convention
	 * @param dfunc is the DWARF function data to test
	 * @return true if the storage locations represent the calling convention
	 */
//	private boolean evaluateParameterStorage(DWARFFunction dfunc) {
//		if (!prog.getRegisterMappings().isUseFormalParameterStorage()) {
//			return false;
//		}
//		for (int i = 0; i < dfunc.params.size(); ++i) {
//			DWARFVariable var = dfunc.params.get(i);
//			if (var.reg == null) {
//				boolean paramsHavePositiveOffset = stackGrowsNegative;
//				if (!var.isStackOffset ||
//					// double check for valid param offset
//					(paramsHavePositiveOffset && var.offset < 0) ||
//					(!paramsHavePositiveOffset && var.offset >= 0)) {
//					return false;
//				}
//			}
//			if (var.type == null) {
//				// this can happen when a parameter doesn't fit into the register that
//				// the dwarf expression helper decoded as the parameter's location.
//				return false;
//			}
//		}
//		return true;
//	}

	private Variable buildVariable(DWARFVariable dvar) throws InvalidInputException {
		Varnode[] vnarray = buildVarnodes(dvar);
		VariableStorage storage = new VariableStorage(currentProgram, vnarray);
		int firstUseOffset = 0;
		if ((dvar.reg != null) && (dvar.offset != -1)) {
			firstUseOffset = (int) dvar.offset;
		}
		return new LocalVariableImpl(dvar.dni.getName(), firstUseOffset, dvar.type, storage,
			currentProgram);
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

	private Varnode[] buildVarnodes(DWARFVariable dvar) {
		if (dvar.type == null) {
			return null;
		}
		Varnode[] retarray = null;
		int typesize = dvar.type.getLength();
		if (dvar.reg != null) {
			retarray = new Varnode[1];
			if (prog.isBigEndian() && (dvar.reg.getMinimumByteSize() > typesize)) {
				retarray[0] = new Varnode(
					dvar.reg.getAddress().add(dvar.reg.getMinimumByteSize() - typesize), typesize);
			}
			else {
				retarray[0] = new Varnode(dvar.reg.getAddress(), typesize);
			}
		}
		else if (dvar.isStackOffset) {
			retarray = new Varnode[1];
			retarray[0] = new Varnode(
				currentProgram.getAddressFactory().getStackSpace().getAddress(dvar.offset),
				typesize);
		}
		return retarray;
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

	private void commitLocal(Function func, DWARFVariable dvar) throws InvalidInputException {
		// Attempt to add the variable
		Variable var = buildVariable(dvar);

		// check for an existing local variable with conflict storage.
		boolean hasConflict = false;
		for (Variable existingVar : func.getAllVariables()) {
			if (existingVar.getFirstUseOffset() == var.getFirstUseOffset() &&
				existingVar.getVariableStorage().intersects(var.getVariableStorage())) {
				if ((existingVar instanceof LocalVariable) &&
					Undefined.isUndefined(existingVar.getDataType())) {
					// ignore locals with undefined type - they will be removed below
					continue;
				}
				hasConflict = true;
				break;
			}
		}
		if (hasConflict) {
			appendComment(func.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
				"Scope for omitted local variable " + var.toString() + " starts here", "; ");
			return;
		}

		try {
			VariableUtilities.checkVariableConflict(func, null, var.getVariableStorage(), true);
			func.addLocalVariable(var, SourceType.IMPORTED);
		}
		catch (DuplicateNameException e) {
			int count = 1;
			// Add the variable with an unused name
			String baseName = var.getName();
			while (!monitor.isCancelled()) {
				try {
					var.setName(baseName + "_" + Integer.toString(count), SourceType.IMPORTED);
					func.addLocalVariable(var, SourceType.IMPORTED);
				}
				catch (DuplicateNameException e1) {
					count++;
					continue;
				}
				break;
			}
		}

	}

	private void processLabel(DIEAggregate diea) {
		if (!shouldProcess(diea)) {
			return;
		}

		String name = prog.getEntryName(diea);
		if (name != null && diea.hasAttribute(DWARFAttribute.DW_AT_low_pc)) {
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
	 * Holds values necessary to create a new variable / parameter.
	 */
	static class DWARFVariable {
		public DWARFNameInfo dni;
		public DataType type;
		public long offset;// Offset on stack or firstuseoffset if this is a register
		public boolean isStackOffset;// true if offset represents stack offset
		public long lexicalOffset;
		public Register reg;
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
}
