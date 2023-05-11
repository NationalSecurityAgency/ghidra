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
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_unspecified_parameters;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a function that was read from DWARF information.
 */
public class DWARFFunction {
	public enum CommitMode {
		SKIP, FORMAL, STORAGE,
	}

	public DIEAggregate diea;
	public DWARFNameInfo name;
	public Namespace namespace;
	public Address address;
	public Address highAddress;
	public long frameBase;	// TODO: change this to preserve the func's frameBase expr instead of value

	public GenericCallingConvention callingConvention;
	public PrototypeModel prototypeModel;

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
		if (isBadSubprogramDef(diea)) {
			return null;
		}

		DWARFProgram prog = diea.getProgram();
		DWARFDataTypeManager dwarfDTM = prog.getDwarfDTM();

		Address funcAddr = prog.getCodeAddress(diea.getLowPC(0));
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
		return prototypeModel != null
				? prototypeModel.getName()
				: callingConvention != null
						? callingConvention.getDeclarationName()
						: null;
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

	public boolean hasConflictWithExistingLocalVariableStorage(DWARFVariable dvar, Function gfunc)
			throws InvalidInputException {
		VariableStorage newVarStorage = dvar.getVariableStorage();
		for (Variable existingVar : gfunc.getAllVariables()) {
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

	public List<String> getExistingLocalVariableNames(Function gfunc) {
		return Arrays.stream(gfunc.getLocalVariables())
				.filter(var -> var.getName() != null && !Undefined.isUndefined(var.getDataType()))
				.map(var -> var.getName())
				.collect(Collectors.toList());
	}
	
	public List<String> getNonParamSymbolNames(Function gfunc) {
		SymbolIterator symbols = gfunc.getProgram().getSymbolTable().getSymbols(gfunc);
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
	 * @throws InvalidInputException
	 */
	public List<Parameter> getParameters(boolean includeStorageDetail)
			throws InvalidInputException {
		List<Parameter> result = new ArrayList<>();
		for (DWARFVariable dvar : params) {
			result.add(dvar.asParameter(includeStorageDetail, getProgram().getGhidraProgram()));
		}
		return result;
	}

	/**
	 * Returns a {@link FunctionDefinition} that reflects this function's information.
	 *  
	 * @return {@link FunctionDefinition} that reflects this function's information
	 */
	public FunctionDefinition asFuncDef() {
		List<ParameterDefinition> funcDefParams = new ArrayList<>();
		for (DWARFVariable param : params) {
			funcDefParams.add(param.asParameterDef());
		}

		FunctionDefinitionDataType funcDef =
			new FunctionDefinitionDataType(name.getParentCP(), name.getName(),
				getProgram().getGhidraProgram().getDataTypeManager());
		funcDef.setReturnType(retval.type);
		funcDef.setArguments(funcDefParams.toArray(ParameterDefinition[]::new));
		funcDef.setGenericCallingConvention(
			Objects.requireNonNullElse(callingConvention, GenericCallingConvention.unknown));
		funcDef.setVarArgs(varArg);

		DWARFSourceInfo sourceInfo = null;
		if (getProgram().getImportOptions().isOutputSourceLocationInfo() &&
			(sourceInfo = DWARFSourceInfo.create(diea)) != null) {
			funcDef.setComment(sourceInfo.getDescriptionStr());
		}

		return funcDef;
	}

	public void commitLocalVariable(DWARFVariable dvar, Function gfunc) {
		
		VariableStorage varStorage = null;
		try {
			varStorage = dvar.getVariableStorage();
			if (hasConflictWithParamStorage(dvar)) {
				appendComment(gfunc.getEntryPoint(), CodeUnit.PLATE_COMMENT,
					"Local variable %s[%s] conflicts with parameter, skipped.".formatted(
						dvar.getDeclInfoString(), varStorage),
					"\n");
				return;
			}

			if (hasConflictWithExistingLocalVariableStorage(dvar, gfunc)) {
				appendComment(gfunc.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
					"Local omitted variable %s[%s] scope starts here".formatted(
						dvar.getDeclInfoString(), varStorage),
					"; ");
				return;
			}

			NameDeduper nameDeduper = new NameDeduper();
			nameDeduper.addReservedNames(getAllLocalVariableNames());
			nameDeduper.addUsedNames(getAllParamNames());
			nameDeduper.addUsedNames(getExistingLocalVariableNames(gfunc));

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

			VariableUtilities.checkVariableConflict(gfunc, var, varStorage, true);
			gfunc.addLocalVariable(var, SourceType.IMPORTED);
		}
		catch (InvalidInputException | DuplicateNameException e) {
			appendComment(gfunc.getEntryPoint().add(dvar.lexicalOffset), CodeUnit.EOL_COMMENT,
				"Local omitted variable %s[%s] scope starts here".formatted(
					dvar.getDeclInfoString(),
					varStorage != null ? varStorage.toString() : "UNKNOWN"),
				"; ");

		}
	}

	@Override
	public String toString() {
		return String.format(
			"DWARFFunction [\n\tdni=%s,\n\taddress=%s,\n\tparams=%s,\n\tsourceInfo=%s,\n\tlocalVarErrors=%s,\n\tretval=%s\n]",
			name, address, params, sourceInfo, localVarErrors, retval);
	}

	private static boolean isBadSubprogramDef(DIEAggregate diea) {
		if (diea.isDanglingDeclaration() || !diea.hasAttribute(DW_AT_low_pc)) {
			return true;
		}

		// fetch the low_pc attribute directly instead of calling diea.getLowPc() to avoid
		// any fixups applied by lower level code
		DWARFNumericAttribute attr =
			diea.getAttribute(DW_AT_low_pc, DWARFNumericAttribute.class);
		if (attr != null && attr.getUnsignedValue() == 0) {
			return true;
		}

		return false;
	}

	private void appendComment(Address address, int commentType, String comment, String sep) {
		DWARFUtil.appendComment(getProgram().getGhidraProgram(), address, commentType, "", comment,
			sep);
	}

}
