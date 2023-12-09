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
import java.util.stream.StreamSupport;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.funcfixup.DWARFFunctionFixup;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;

/**
 * Represents a function that was read from DWARF information.
 */
public class DWARFFunction {
	public enum CommitMode { SKIP, FORMAL, STORAGE, }

	public DIEAggregate diea;
	public DWARFNameInfo name;
	public Namespace namespace;
	public Address address;
	public Address highAddress;
	public long frameBase;	// TODO: change this to preserve the func's frameBase expr instead of value
	public Function function;	// ghidra function

	public String callingConventionName;

	public DWARFVariable retval;
	public List<DWARFVariable> params = new ArrayList<>();
	public boolean varArg;
	public List<DWARFVariable> localVars = new ArrayList<>();
	// We keep track of local var errors here because local variables aren't added
	// to the local's list if they are problematic
	public boolean localVarErrors;
	public CommitMode signatureCommitMode = CommitMode.STORAGE;

	public boolean noReturn;
	public DWARFSourceInfo sourceInfo;
	public boolean isExternal;

	/**
	 * Create a function instance from the information found in the specified DIEA.
	 * 
	 * @param diea DW_TAG_subprogram {@link DIEAggregate}
	 * @return new {@link DWARFFunction}, or null if invalid DWARF information 
	 * @throws IOException if error accessing attribute values
	 * @throws DWARFExpressionException if error accessing attribute values
	 */
	public static DWARFFunction read(DIEAggregate diea)
			throws IOException, DWARFExpressionException {
		if (diea.isDanglingDeclaration()) {
			return null;
		}
		Address funcAddr = getFuncEntry(diea);
		if (funcAddr == null) {
			return null;
		}

		DWARFProgram prog = diea.getProgram();
		DWARFDataTypeManager dwarfDTM = prog.getDwarfDTM();

		DWARFFunction dfunc = new DWARFFunction(diea, prog.getName(diea), funcAddr);

		dfunc.namespace = dfunc.name.getParentNamespace(prog.getGhidraProgram());
		dfunc.sourceInfo = DWARFSourceInfo.create(diea);

		dfunc.highAddress =
			diea.hasAttribute(DW_AT_high_pc) ? prog.getCodeAddress(diea.getHighPC()) : null;

		// Check if the function is an external function
		dfunc.isExternal = diea.getBool(DW_AT_external, false);
		dfunc.noReturn = diea.getBool(DW_AT_noreturn, false);

		// Retrieve the frame base if it exists
		DWARFLocation frameLoc = null;
		if (diea.hasAttribute(DW_AT_frame_base)) {
			List<DWARFLocation> frameBase = diea.getAsLocation(DW_AT_frame_base, dfunc.getRange());
			// get the framebase register, find where the frame is finally setup.
			frameLoc = DWARFLocation.getTopLocation(frameBase, dfunc.address.getOffset());
			if (frameLoc != null) {
				dfunc.frameBase = (int) diea.evaluateLocation(frameLoc);
			}
		}

		dfunc.retval =
			DWARFVariable.fromDataType(dfunc, dwarfDTM.getDataTypeForVariable(diea.getTypeRef()));

		int paramOrdinal = 0;
		for (DIEAggregate paramDIEA : diea.getFunctionParamList()) {
			DWARFVariable param = DWARFVariable.readParameter(paramDIEA, dfunc, paramOrdinal++);
			dfunc.params.add(param);
		}
		dfunc.varArg = !diea.getChildren(DW_TAG_unspecified_parameters).isEmpty();

		return dfunc;
	}

	private DWARFFunction(DIEAggregate diea, DWARFNameInfo dni, Address address) {
		this.diea = diea;
		this.name = dni;
		this.address = address;
	}

	public DWARFProgram getProgram() {
		return diea.getProgram();
	}

	public DWARFRange getRange() {
		return new DWARFRange(address.getOffset(),
			highAddress != null ? highAddress.getOffset() : address.getOffset() + 1);
	}

	public String getCallingConventionName() {
		return callingConventionName;
	}

	/**
	 * Returns the DWARFVariable that starts at the specified stack offset.
	 * 
	 * @param offset stack offset
	 * @return local variable that starts at offset, or null if not present
	 */
	public DWARFVariable getLocalVarByOffset(long offset) {
		for (DWARFVariable localVar : localVars) {
			if (localVar.isStackStorage() && localVar.getStackOffset() == offset) {
				return localVar;
			}
		}
		return null;
	}

	/**
	 * Returns true if the specified stack offset is within the function's local variable
	 * storage area.
	 * 
	 * @param offset stack offset to test
	 * @return true if stack offset is within this function's local variable area
	 */
	public boolean isInLocalVarStorageArea(long offset) {
		boolean paramsHavePositiveOffset = diea.getProgram().stackGrowsNegative();
		return (paramsHavePositiveOffset && offset < 0) ||
			(!paramsHavePositiveOffset && offset >= 0);
	}

	public boolean hasConflictWithParamStorage(DWARFVariable dvar) throws InvalidInputException {
		if (dvar.lexicalOffset != 0) {
			return false;
		}
		VariableStorage storage = dvar.getVariableStorage();
		for (DWARFVariable param : params) {
			VariableStorage paramStorage = param.getVariableStorage();
			if (paramStorage.intersects(storage)) {
				return true;
			}
		}
		return false;
	}

	public boolean hasConflictWithExistingLocalVariableStorage(DWARFVariable dvar)
			throws InvalidInputException {
		VariableStorage newVarStorage = dvar.getVariableStorage();
		for (Variable existingVar : function.getAllVariables()) {
			if (existingVar.getFirstUseOffset() == dvar.lexicalOffset &&
				existingVar.getVariableStorage().intersects(newVarStorage)) {
				if ((existingVar instanceof LocalVariable) &&
					Undefined.isUndefined(existingVar.getDataType())) {
					continue;
				}
				return true;
			}
		}
		return false;
	}

	public List<String> getAllParamNames() {
		return params.stream()
				.filter(dvar -> !dvar.name.isAnon())
				.map(dvar -> dvar.name.getName())
				.collect(Collectors.toList());
	}

	public List<String> getAllLocalVariableNames() {
		return localVars.stream()
				.filter(dvar -> !dvar.name.isAnon())
				.map(dvar -> dvar.name.getName())
				.collect(Collectors.toList());
	}

	public List<String> getExistingLocalVariableNames() {
		return Arrays.stream(function.getLocalVariables())
				.filter(var -> var.getName() != null && !Undefined.isUndefined(var.getDataType()))
				.map(var -> var.getName())
				.collect(Collectors.toList());
	}

	public List<String> getNonParamSymbolNames() {
		SymbolIterator symbols = function.getProgram().getSymbolTable().getSymbols(function);
		return StreamSupport.stream(symbols.spliterator(), false)
				.filter(symbol -> symbol.getSymbolType() != SymbolType.PARAMETER)
				.map(Symbol::getName)
				.collect(Collectors.toList());
	}

	/**
	 * Returns this function's parameters as a list of {@link Parameter} instances.
	 * 
	 * @param includeStorageDetail boolean flag, if true storage information will be included, if
	 * false, VariableStorage.UNASSIGNED_STORAGE will be used
	 * @return list of Parameters
	 * @throws InvalidInputException if bad information in param storage
	 */
	public List<Parameter> getParameters(boolean includeStorageDetail)
			throws InvalidInputException {
		List<Parameter> result = new ArrayList<>();
		for (DWARFVariable dvar : params) {
			result.add(dvar.asParameter(includeStorageDetail));
		}
		return result;
	}

	/**
	 * Returns the parameters of this function as {@link ParameterDefinition}s.
	 * 
	 * @return array of {@link ParameterDefinition}s
	 */
	public ParameterDefinition[] getParameterDefinitions() {
		return params.stream()
				.map(dvar -> new ParameterDefinitionImpl(dvar.name.getName(), dvar.type, null))
				.toArray(ParameterDefinition[]::new);
	}

	public void commitLocalVariable(DWARFVariable dvar) {

		VariableStorage varStorage = null;
		try {
			varStorage = dvar.getVariableStorage();
			if (hasConflictWithParamStorage(dvar)) {
				appendComment(function.getEntryPoint(), CodeUnit.PLATE_COMMENT,
					"Local variable %s[%s] conflicts with parameter, skipped."
							.formatted(dvar.getDeclInfoString(), varStorage),
					"\n");
				return;
			}

			if (hasConflictWithExistingLocalVariableStorage(dvar)) {
				appendComment(function.getEntryPoint().add(dvar.lexicalOffset),
					CodeUnit.EOL_COMMENT, "Local omitted variable %s[%s] scope starts here"
							.formatted(dvar.getDeclInfoString(), varStorage),
					"; ");
				return;
			}

			NameDeduper nameDeduper = new NameDeduper();
			nameDeduper.addReservedNames(getAllLocalVariableNames());
			nameDeduper.addUsedNames(getAllParamNames());
			nameDeduper.addUsedNames(getExistingLocalVariableNames());

			Variable var = dvar.asLocalVariable();
			String origName = var.getName();
			String newName = nameDeduper.getUniqueName(origName);
			if (newName != null) {
				try {
					var.setName(newName, null);
				}
				catch (DuplicateNameException | InvalidInputException e) {
					// can't happen
				}
				var.setComment("Original name: " + origName);
			}

			VariableUtilities.checkVariableConflict(function, var, varStorage, true);
			function.addLocalVariable(var, SourceType.IMPORTED);
		}
		catch (InvalidInputException | DuplicateNameException e) {
			appendComment(function.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
				"Local omitted variable %s[%s] scope starts here".formatted(
					dvar.getDeclInfoString(),
					varStorage != null ? varStorage.toString() : "UNKNOWN"),
				"; ");

		}
	}

	private static boolean isBadSubprogramDef(DIEAggregate diea) {
		if (diea.isDanglingDeclaration() || !diea.hasAttribute(DW_AT_low_pc)) {
			return true;
		}

		// fetch the low_pc attribute directly instead of calling diea.getLowPc() to avoid
		// any fixups applied by lower level code
		DWARFNumericAttribute attr = diea.getAttribute(DW_AT_low_pc, DWARFNumericAttribute.class);
		if (attr != null && attr.getUnsignedValue() == 0) {
			return true;
		}

		return false;
	}

	private void appendComment(Address address, int commentType, String comment, String sep) {
		DWARFUtil.appendComment(getProgram().getGhidraProgram(), address, commentType, "", comment,
			sep);
	}

	//---------------------------------------------------------------------------------------------

	private static Address getFuncEntry(DIEAggregate diea) throws IOException {
		// TODO: dw_at_entry_pc is also sometimes available, typically in things like inlined_subroutines 
		DWARFProgram dprog = diea.getProgram();
		DWARFNumericAttribute lowpcAttr =
			diea.getAttribute(DW_AT_low_pc, DWARFNumericAttribute.class);
		if (lowpcAttr != null && lowpcAttr.getUnsignedValue() != 0) {
			return dprog.getCodeAddress(
				lowpcAttr.getUnsignedValue() + dprog.getProgramBaseAddressFixup());
		}
		if (diea.hasAttribute(DW_AT_ranges)) {
			List<DWARFRange> bodyRanges = diea.readRange(DW_AT_ranges);
			if (!bodyRanges.isEmpty()) {
				return dprog.getCodeAddress(bodyRanges.get(0).getFrom());
			}
		}
		return null;
	}

	public boolean syncWithExistingGhidraFunction(boolean createIfMissing) {
		try {
			Program currentProgram = getProgram().getGhidraProgram();
			function = currentProgram.getListing().getFunctionAt(address);
			if (function != null) {
				if (function.hasNoReturn() && !noReturn) {
					// preserve the noReturn flag if set by earlier analyzer
					noReturn = true;
				}
			}

			if (!createIfMissing && function == null) {
				return false;
			}

			// create a new symbol if one does not exist (symbol table will figure this out)
			SymbolTable symbolTable = currentProgram.getSymbolTable();
			symbolTable.createLabel(address, name.getName(), namespace, SourceType.IMPORTED);

			// force new label to become primary (if already a function it will become function name)
			SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, name.getName(), namespace);
			cmd.applyTo(currentProgram);

			if (isExternal) {
				currentProgram.getSymbolTable().addExternalEntryPoint(address);
			}
			else {
				currentProgram.getSymbolTable().removeExternalEntryPoint(address);
			}

			function = currentProgram.getListing().getFunctionAt(address);
			if (function == null) {

				// TODO: If not contained within program memory should they be considered external?
				if (!currentProgram.getMemory()
						.getLoadedAndInitializedAddressSet()
						.contains(address)) {
					Msg.warn(this,
						"DWARF: unable to create function not contained within loaded memory: %s@%s"
								.formatted(name, address));
					return false;
				}

				// create 1-byte function if one does not exist - primary label will become function names
				function = currentProgram.getFunctionManager()
						.createFunction(null, address, new AddressSet(address),
							SourceType.IMPORTED);
			}

			return true;
		}
		catch (OverlappingFunctionException e) {
			throw new AssertException(e);
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Failed to create function " + namespace + "/" + name.getName() + ": " +
				e.getMessage());
		}
		return false;
	}

	public void runFixups() {
		// Run all the DWARFFunctionFixup instances
		for (DWARFFunctionFixup fixup : getProgram().getFunctionFixups()) {
			try {
				fixup.fixupDWARFFunction(this);
			}
			catch (DWARFException e) {
				signatureCommitMode = CommitMode.SKIP;
			}
			if (signatureCommitMode == CommitMode.SKIP) {
				break;
			}
		}
	}

	public void updateFunctionSignature() {
		try {
			boolean includeStorageDetail = signatureCommitMode == CommitMode.STORAGE;
			FunctionUpdateType functionUpdateType = includeStorageDetail
					? FunctionUpdateType.CUSTOM_STORAGE
					: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;

			Parameter returnVar = retval.asReturnParameter(includeStorageDetail);
			List<Parameter> parameters = getParameters(includeStorageDetail);

			if (includeStorageDetail && !retval.isZeroByte() && retval.isMissingStorage()) {
				// TODO: this logic is faulty and borks the auto _return_storage_ptr_ when present
				// Update return value in a separate step as its storage isn't typically specified
				// in dwarf info.
				// This will allow automagical storage assignment for return value by ghidra.
				function.updateFunction(callingConventionName, returnVar, List.of(),
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.IMPORTED);
				returnVar = null; // don't update it in the second call to updateFunction()
			}

			function.updateFunction(callingConventionName, returnVar, parameters,
				functionUpdateType, true, SourceType.IMPORTED);
			function.setVarArgs(varArg);
			function.setNoReturn(noReturn);
		}
		catch (InvalidInputException | DuplicateNameException e) {
			Msg.error(this, "Error updating function %s@%s with params: %s".formatted(
				function.getName(), function.getEntryPoint().toString(), e.getMessage()));
			Msg.error(this, "DIE info: " + diea.toString());
		}
	}

	/**
	 * Returns a {@link FunctionDefinition} that reflects this function's information.
	 *  
	 * @param includeCC boolean flag, if true the returned funcdef will include calling convention 
	 * @return {@link FunctionDefinition} that reflects this function's information
	 */
	public FunctionDefinition asFunctionDefinition(boolean includeCC) {
		ProgramBasedDataTypeManager dtm = getProgram().getGhidraProgram().getDataTypeManager();

		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(name.getParentCP(), name.getName(), dtm);
		funcDef.setReturnType(retval.type);
		funcDef.setNoReturn(noReturn);
		funcDef.setArguments(getParameterDefinitions());
		if (varArg) {
			funcDef.setVarArgs(true);
		}
		if (getProgram().getImportOptions().isOutputSourceLocationInfo() && sourceInfo != null) {
			funcDef.setComment(sourceInfo.getDescriptionStr());
		}
		if (includeCC && callingConventionName != null) {
			try {
				funcDef.setCallingConvention(callingConventionName);
			}
			catch (InvalidInputException e) {
				Msg.warn(this, "Unable to set calling convention name to %s for function def: %s"
						.formatted(callingConventionName, funcDef));
			}
		}

		return funcDef;
	}

	@Override
	public String toString() {
		return String.format(
			"DWARFFunction [name=%s, address=%s, sourceInfo=%s, retval=%s, params=%s, function=%s, diea=%s, signatureCommitMode=%s]",
			name, address, sourceInfo, retval, params, function, diea, signatureCommitMode);
	}

}
