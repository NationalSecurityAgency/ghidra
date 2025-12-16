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

import static ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute.*;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf.expression.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Represents a function's parameter or local variable; or a global variable. 
 */
public class DWARFVariable {
	/**
	 * Creates an unnamed, storage-less {@link DWARFVariable} from a DataType.
	 *  
	 * @param dfunc containing function 
	 * @param dt {@link DataType} of the variable
	 * @return new {@link DWARFVariable}, never null
	 */
	public static DWARFVariable fromDataType(DWARFFunction dfunc, DataType dt) {
		return new DWARFVariable(dfunc.getProgram(), dfunc, dt);
	}

	/**
	 * Reads a parameter.
	 * 
	 * @param diea {@link DIEAggregate} DW_TAG_formal_parameter
	 * @param dfunc {@link DWARFFunction} that this parameter is attached to
	 * @param paramOrdinal ordinal in containing list
	 * @return new parameter, never null, possibly without storage info 
	 */
	public static DWARFVariable readParameter(DIEAggregate diea, DWARFFunction dfunc,
			int paramOrdinal) {

		DWARFVariable dvar = new DWARFVariable(dfunc, diea);
		dvar.isOutputParameter = diea.getBool(DW_AT_variable_parameter, false);
		dvar.isThis = paramOrdinal == 0 && DWARFUtil.isThisParam(diea);
		dvar.readParamStorage(diea);

		return dvar;
	}

	/**
	 * Reads a local variable.
	 * 
	 * @param diea {@link DIEAggregate} DW_TAG_variable
	 * @param dfunc {@link DWARFFunction} that this local var belongs to
	 * @param offsetFromFuncStart offset from start of containing function
	 * @return new DWARFVariable that represents a local var, never null.  Check
	 * {@link #isMissingStorage()} to determine if there was an error getting storage info
	 */
	public static DWARFVariable readLocalVariable(DIEAggregate diea, DWARFFunction dfunc,
			long offsetFromFuncStart) {
		// local variable without location information is useless, so return null in those cases
		DWARFVariable dvar = new DWARFVariable(dfunc, diea);
		dvar.lexicalOffset = offsetFromFuncStart;

		dvar.readLocalVariableStorage(diea);

		return dvar;
	}

	/**
	 * Reads a static/global variable.
	 * 
	 * @param diea {@link DIEAggregate} DW_TAG_variable
	 * @return new {@link DWARFVariable} that represents the global variable, or
	 * <strong>null</strong> if error reading storage info
	 */
	public static DWARFVariable readGlobalVariable(DIEAggregate diea) {
		DWARFVariable dvar = new DWARFVariable(null, diea);
		SymbolType globalVarSymbolType = null; // TODO: need better symbol type, nothing matches static global var
		dvar.name = dvar.name.replaceType(globalVarSymbolType);

		return dvar.readGlobalStorage(diea) ? dvar : null;
	}

	private final DWARFProgram program;
	private final DWARFFunction dfunc;
	public DWARFName name;
	public DataType type;
	public long lexicalOffset; // offset inside function where variable storage becomes valid
	public boolean isOutputParameter;	// changes to parameter value escape back to the calling location
	public boolean isExternal;
	public boolean isThis;
	public DWARFSourceInfo sourceInfo;
	private List<Varnode> storage = new ArrayList<>();
	private Varnode stackStorage; // any stack storage is forced to be last in the storage list
	public String comment;

	private DWARFVariable(DWARFProgram program, DWARFFunction dfunc, DataType type) {
		this.program = program;
		this.dfunc = dfunc;
		this.type = type;
	}

	private DWARFVariable(DWARFFunction dfunc, DIEAggregate diea) {
		this.program = diea.getProgram();
		this.dfunc = dfunc;
		this.name = program.getName(diea);
		this.type = program.getDwarfDTM().getDataTypeForVariable(diea.getTypeRef());
		this.isExternal = diea.getBool(DW_AT_external, false);
		this.sourceInfo = DWARFSourceInfo.create(diea);
	}

	public void setStorage(Varnode varnode) {
		clearStorage();
		if (varnode.getSize() == 0) {
			// TODO: size probably needs to drive register adjustments
			varnode = new Varnode(varnode.getAddress(), type.getLength());
		}
		if ( DWARFUtil.isStackVarnode(varnode)) {
			stackStorage = varnode;
		} else {
			storage.add(varnode);
		}
	}

	/**
	 * Assign storage for this variable in a ram data location.
	 * 
	 * @param offset address offset
	 */
	public void setRamStorage(long offset) {
		clearStorage();
		addRamStorage(offset);
	}

	public void addRamStorage(long offset) {
		storage.add(new Varnode(program.getDataAddress(offset), type.getLength()));
	}

	/**
	 * Assign storage for this variable at a stack offset.
	 * 
	 * @param offset stack offset
	 */
	public void setStackStorage(long offset) {
		clearStorage();
		addStackStorage(offset, type.getLength());
	}

	public void addStackStorage(long offset, int length) {
		if (stackStorage == null) {
			stackStorage = new Varnode(program.getStackSpace().getAddress(offset), length);
		}
		else {
			if (stackStorage.getOffset() + stackStorage.getSize() > offset) {
				throw new IllegalArgumentException("Overlaps previous stack allocation");
			}
			stackStorage = new Varnode(program.getStackSpace().getAddress(stackStorage.getOffset()),
				(int) (offset - stackStorage.getOffset() + length));
		}
	}

	/**
	 * Assign storage for this variable via a list of registers.
	 * 
	 * @param registers registers that contain the data 
	 */
	public void setRegisterStorage(List<Register> registers) {
		clearStorage();
		addRegisterStorage(registers);
	}

	public void addRegisterStorage(List<Register> registers) {
		List<Varnode> varnodes =
			DWARFUtil.convertRegisterListToVarnodeStorage(registers, type.getLength());
		storage.addAll(varnodes);
	}

	/**
	 * @return true if this variable is stored on the stack
	 */
	public boolean isStackStorage() {
		return storage.isEmpty() && stackStorage != null;
	}

	/**
	 * If this is a stack variable, return its stack offset.
	 * 
	 * @return its stack offset
	 */
	public long getStackOffset() {
		if (!isStackStorage()) {
			throw new IllegalArgumentException();
		}
		return stackStorage.getOffset();
	}

	/**
	 * @return true if this variable's storage is in ram
	 */
	public boolean isRamStorage() {
		return storage.size() == 1 && storage.get(0).isAddress();
	}

	/**
	 * If this is a static/global variable, stored at a ram address, return it's
	 * ram address.
	 * 
	 * @return address of where this variable is stored, null if not ram address
	 */
	public Address getRamAddress() {
		return isRamStorage() ? storage.get(0).getAddress() : null;
	}

	public boolean isMissingStorage() {
		return storage.isEmpty() && stackStorage == null;
	}

	public boolean isZeroByte() {
		return DWARFUtil.isZeroByteDataType(type);
	}

	public boolean isVoidType() {
		return DWARFUtil.isVoid(type);
	}

	public boolean isEmptyArray() {
		return DWARFUtil.isEmptyArray(type);
	}

	public boolean isLocationValidOnEntry() {
		return lexicalOffset == 0;
	}

	public void clearStorage() {
		storage.clear();
		stackStorage = null;
	}

	private boolean readParamStorage(DIEAggregate diea) {
		try {
			if (DataTypeComponent.usesZeroLengthComponent(type)) {
				program.getImportSummary().paramZeroLenDataType++;
				program.logWarningAt(dfunc.address, dfunc.name.getName(),
					"Zero-length function parameter: %s : %s".formatted(name.getName(),
						type.getName()));
				return false;
			}
			DWARFLocation paramLoc = diea.getLocation(DW_AT_location, dfunc.getEntryPc());
			if (paramLoc == null) {
				return false;
			}
			return readStorage(diea, paramLoc, false);
		}
		catch (IOException e) {
			diea.getProgram().getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readLocalVariableStorage(DIEAggregate diea) {
		try {
			DWARFLocation location = diea.getLocation(DW_AT_location, dfunc.getEntryPc());
			if (location == null) {
				return false;
			}
			if (lexicalOffset == 0) {
				// Don't override the lexical block's start offset (if set)
				// with the address from the dwarf range.  This gives slightly better results with
				// test binaries in the decompiler, but might be wrong for other toolchains.
				// If it causes problems, always use the address from the location's range.
				lexicalOffset = location.getOffset(dfunc.getEntryPc());
			}

			return readStorage(diea, location, true);
		}
		catch (IOException e) {
			diea.getProgram().getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readGlobalStorage(DIEAggregate diea) {
		DWARFProgram prog = diea.getProgram();

		try {
			DWARFLocationList locList = diea.getLocationList(DW_AT_location);
			DWARFLocation location = locList.getFirstLocation();
			if (location == null) {
				return false;
			}

			DWARFExpressionEvaluator exprEvaluator =
				new DWARFExpressionEvaluator(diea.getCompilationUnit());

			exprEvaluator.evaluate(location.getExpr());
			Varnode res = exprEvaluator.popVarnode();

			if (!res.isAddress()) {
				Msg.warn(this, "DWARF: bad location for global variable %s: %s"
						.formatted(getDeclInfoString(), exprEvaluator.getExpr().toString()));
				return false;
			}
			if (res.getAddress().getOffset() == 0) {
				if (diea.hasAttribute(DWARFAttribute.DW_AT_const_value)) {
					// skip without complaining global vars with a const value and bad location expression 
					return false;
				}

				// If the expression evaluated to a static address of '0'.
				// This case is probably caused by relocation fixups not being applied to the
				// .debug_info section.
				prog.getImportSummary().relocationErrorVarDefs.add("%s:%s".formatted(
					name.getNamespacePath().asFormattedString(), type.getPathName()));
				return false;
			}

			setStorage(res);
			return true;
		}
		catch (DWARFExpressionException e) {
			prog.getImportSummary().addProblematicDWARFExpression(e.getExpression());
			return false;
		}
		catch (IOException e) {
			prog.getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readStorage(DIEAggregate diea, DWARFLocation location,
			boolean allowDerefFixup) {

		if (location == null) {
			return false;
		}

		lexicalOffset = location.getOffset(dfunc.address.getOffset());

		DWARFProgram prog = diea.getProgram();
		DWARFImportSummary importSummary = prog.getImportSummary();
		DWARFCompilationUnit cu = diea.getCompilationUnit();

		DWARFExpressionEvaluator exprEvaluator = new DWARFExpressionEvaluator(cu);
		if (dfunc.funcEntryFrameBaseLoc != null &&
			dfunc.funcEntryFrameBaseLoc.getResolvedValue() != null &&
			dfunc.funcEntryFrameBaseLoc.contains(dfunc.getEntryPc() + lexicalOffset)) {
			exprEvaluator.setFrameBaseVal(dfunc.funcEntryFrameBaseLoc.getResolvedValue());
		}

		DWARFExpression expr = null;
		try {
			expr = DWARFExpression.read(location.getExpr(), cu);
			if (expr.isEmpty()) {
				return false;
			}

			if (prog.getImportOptions().isUseStaticStackFrameRegisterValue()) {
				exprEvaluator.setValReader(exprEvaluator.withStaticStackRegisterValues(null,
					prog.getRegisterMappings().getStackFrameRegisterOffset()));
			}

			if (prog.getImportOptions().isShowVariableStorageInfo()) {
				comment = expr.toString(cu);
			}
			
			exprEvaluator.evaluate(expr);
			
			Varnode storageLoc = exprEvaluator.popVarnode();

			setStorage(storageLoc);

			return true;
		}
		catch (DWARFExpressionException e) {
			if (allowDerefFixup && e instanceof DWARFExpressionTerminalDerefException derefExcept) {
				type = type.getDataTypeManager().getPointer(type);
				setStorage(derefExcept.getVarnode());
				return true;
			}

			if (e instanceof DWARFExpressionValueException && expr != null) {
				comment = expr.toString(cu);
			}

			importSummary.addProblematicDWARFExpression(e.getExpression());
			return false;
		}
	}

	public int getStorageSize() {
		return getVarnodes().stream().mapToInt(Varnode::getSize).sum();
	}

	private Varnode[] getVarnodesAsArray() {
		Varnode[] result = new Varnode[storage.size() + (stackStorage != null ? 1 : 0)];
		storage.toArray(result);
		if (stackStorage != null) {
			result[storage.size()] = stackStorage;
		}
		return result;
	}

	public List<Varnode> getVarnodes() {
		List<Varnode> tmp = new ArrayList<>(storage);
		if (stackStorage != null) {
			// add stack storage to the front for LE and back of the list for BE
			tmp.add(program.isBigEndian() ? tmp.size() : 0, stackStorage);
		}
		return tmp;
	}

	public void setVarnodes(List<Varnode> newStorage) {
		clearStorage();
		this.storage = newStorage;
		Varnode lastNode = !storage.isEmpty() ? storage.get(storage.size() - 1) : null;
		if (lastNode != null && DWARFUtil.isStackVarnode(lastNode)) {
			stackStorage = lastNode;
			storage.remove(storage.size() - 1);
		}
	}

	public VariableStorage getVariableStorage() throws InvalidInputException {
		Varnode[] varnodes = getVarnodesAsArray();
		return varnodes.length != 0
				? new VariableStorage(program.getGhidraProgram(), varnodes)
				: VariableStorage.UNASSIGNED_STORAGE;
	}

	public Variable asLocalVariable() throws InvalidInputException {
		int firstUseOffset = !isStackStorage() ? (int) lexicalOffset : 0;

		LocalVariableImpl result = new LocalVariableImpl(name.getName(), firstUseOffset, type,
			getVariableStorage(), program.getGhidraProgram());
		result.setComment(comment);

		return result;
	}

	public Parameter asParameter(boolean includeStorageDetail) throws InvalidInputException {
		VariableStorage paramStorage = !isMissingStorage() && includeStorageDetail
				? getVariableStorage()
				: VariableStorage.UNASSIGNED_STORAGE;

		// try to allow ghidra to autoname param instead of using our autogenerated version
		String newName = name.isAnon() ? null : name.getName();

		ParameterImpl result =
			new ParameterImpl(newName, Parameter.UNASSIGNED_ORDINAL, type, paramStorage, true,
				program.getGhidraProgram(), SourceType.IMPORTED);
		result.setComment(getParamComment());

		return result;
	}

	private String getParamComment() {
		if (!isOutputParameter) {
			return comment;
		}
		return Objects.requireNonNullElse(comment, "") + "(Output Parameter)";

	}

	public ParameterDefinition asParameterDef() {
		return new ParameterDefinitionImpl(name.getOriginalName(), type, getParamComment());
	}

	public Parameter asReturnParameter(boolean includeStorageDetail)
			throws InvalidInputException {
		VariableStorage varStorage = isVoidType()
				? VariableStorage.VOID_STORAGE
				: !isMissingStorage() && includeStorageDetail
						? getVariableStorage()
						: VariableStorage.UNASSIGNED_STORAGE;
		return new ReturnParameterImpl(type, varStorage, true, program.getGhidraProgram());
	}

	public String getDeclInfoString() {
		return "%s:%s".formatted(name.getName(), type.getDisplayName());
	}

	@Override
	public String toString() {
		try {
			return "DWARFVariable [\n\t\tdni=%s,\n\t\ttype=%s,\n\t\tstorage=%s,\n\t\tisOutputParameter=%s\n\t]"
					.formatted(name, type, getVariableStorage().toString(), isOutputParameter);
		}
		catch (InvalidInputException e) {
			return "";
		}
	}

}
