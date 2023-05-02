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

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.dwarf4.*;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.expression.*;
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
 * Represents a function parameter, local variable, or global variable. 
 */
public class DWARFVariable {
	/**
	 * Creates an unnamed, storage-less {@link DWARFVariable} from a DataType. 
	 * 
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
	 * @param paramOrdinal 
	 * @return new parameter, never null, possibly without storage info 
	 * @throws IOException if error
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
	 * @return new DWARFVariable that represents a local var, or <strong>null</strong> if 
	 * error reading storage info
	 */
	public static DWARFVariable readLocalVariable(DIEAggregate diea, DWARFFunction dfunc,
			long offsetFromFuncStart) {
		// local variable without location information is useless, so return null in those cases
		DWARFVariable dvar = new DWARFVariable(dfunc, diea);
		dvar.lexicalOffset = offsetFromFuncStart;

		return dvar.readLocalVariableStorage(diea) ? dvar : null;
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
	public DWARFNameInfo name;
	public DataType type;
	public long lexicalOffset; // offset inside function where variable storage becomes valid
	public boolean isOutputParameter;	// changes to parameter value escape back to the calling location
	public boolean isExternal;
	public boolean isThis;
	public DWARFSourceInfo sourceInfo;
	private List<Varnode> storage = new ArrayList<>();
	private Varnode stackStorage; // any stack storage is forced to be last in the storage list
	private String comment;

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

	public String getToolTip() {
		return """
				<html>Built In Data Types<br>
				&nbsp;&nbsp;%s
				""".formatted("DEFAULT_DATA_ORG_DESCRIPTION");
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
				Msg.warn(this, "DWARF: zero-length function parameter %s:%s in %s@%s".formatted(
					name.getName(), type.getName(), dfunc.name.getName(), dfunc.address));
				return false;
			}
			DWARFLocation topLocation = DWARFLocation.getTopLocation(
				diea.getAsLocation(DW_AT_location, dfunc.getRange()), dfunc.address.getOffset());
			if (topLocation == null) {
				return false;
			}
			return readStorage(diea, topLocation);
		}
		catch (IOException e) {
			diea.getProgram().getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readLocalVariableStorage(DIEAggregate diea) {
		try {
			DWARFLocation location = DWARFLocation
					.getFirstLocation(diea.getAsLocation(DW_AT_location, dfunc.getRange()));
			if (location == null) {
				return false;
			}
			if (lexicalOffset == 0) {
				// Don't override the lexical block's start offset (if set)
				// with the address from the dwarf range.  This gives slightly better results with
				// test binaries in the decompiler, but might be wrong for other toolchains.
				// If it causes problems, always use the address from the location's range.
				lexicalOffset = location.getRange().getFrom() - dfunc.address.getOffset();
			}

			return readStorage(diea, location);
		}
		catch (IOException e) {
			diea.getProgram().getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readGlobalStorage(DIEAggregate diea) {
		DWARFProgram prog = diea.getProgram();

		try {
			DWARFLocation location = DWARFLocation
					.getFirstLocation(diea.getAsLocation(DW_AT_location, DWARFRange.EMPTY));
			if (location == null) {
				return false;
			}

			DWARFExpressionEvaluator exprEvaluator =
				DWARFExpressionEvaluator.create(diea.getHeadFragment());

			DWARFExpression expr = exprEvaluator.readExpr(location.getLocation());

			exprEvaluator.evaluate(expr);
			if (exprEvaluator.getRawLastRegister() != -1) {
				Msg.warn(this, "DWARF: bad location for global variable %s: %s"
						.formatted(getDeclInfoString(), expr.toString()));
				return false;
			}

			long res = exprEvaluator.pop();
			if (res == 0) {
				// If the expression evaluated to a static address of '0'.
				// This case is probably caused by relocation fixups not being applied to the
				// .debug_info section.
				prog.getImportSummary().relocationErrorVarDefs.add("%s:%s".formatted(
					name.getNamespacePath().asFormattedString(), type.getPathName()));
				return false;
			}

			setRamStorage(res + prog.getProgramBaseAddressFixup());
			return true;
		}
		catch (DWARFExpressionException | UnsupportedOperationException
				| IndexOutOfBoundsException | IOException ex) {
			prog.getImportSummary().exprReadError++;
			return false;
		}
	}

	private boolean readStorage(DIEAggregate diea, DWARFLocation location) {

		if (location == null) {
			return false;
		}

		lexicalOffset = location.getRange().getFrom() - dfunc.address.getOffset();

		DWARFProgram prog = diea.getProgram();
		DWARFImportSummary importSummary = prog.getImportSummary();

		try {
			DWARFExpressionEvaluator exprEvaluator =
				DWARFExpressionEvaluator.create(diea.getHeadFragment());
			exprEvaluator.setFrameBase(dfunc.frameBase);

			DWARFExpression expr = exprEvaluator.readExpr(location.getLocation());

			exprEvaluator.evaluate(expr);
			long res = exprEvaluator.pop();

			// check expression eval result.  Use early return for errors, leaving storage unset.
			// Success return is at bottom of if/else chain of checks.

			if (exprEvaluator.isDwarfStackValue()) {
				// result is a value (not a location) left on the expr stack, which is not supported 
				importSummary.varDWARFExpressionValue++;
				return false;
			}

			if (exprEvaluator.useUnknownRegister()) {
				// This is a deref of a register (excluding the stack pointer)
				// If the offset of the deref was 0, we can cheese it into a ghidra register location
				// by changing the datatype to a pointer-to-original-datatype, otherwise
				// its not usable in ghidra

				if (!exprEvaluator.isRegisterLocation()) {
					importSummary.varDynamicRegisterError++;
					return false;
				}

				type = prog.getDwarfDTM().getPtrTo(type);
				setRegisterStorage(List.of(exprEvaluator.getLastRegister()));
			}
			else if (exprEvaluator.isStackRelative()) {
				if (exprEvaluator.isDeref()) {
					type = prog.getDwarfDTM().getPtrTo(type);
				}
				setStackStorage(res);
			}
			else if (exprEvaluator.isRegisterLocation()) {
				// The DWARF expression evaluated to a simple register.  If we have a mapping
				// for it in the "processor.dwarf" register mapping file, try to create
				// a variable, otherwise log the unknown register for later logging.
				Register reg = exprEvaluator.getLastRegister();
				if (reg == null) {
					// The DWARF register did not have a mapping to a Ghidra register, so
					// log it to be displayed in an error summary at end of import phase.
					importSummary.unknownRegistersEncountered
							.add(exprEvaluator.getRawLastRegister());
					return false;
				}
				if ((type.getLength() > reg.getMinimumByteSize())) {
					importSummary.varFitError++;

					Msg.warn(this,
						"%s %s [%s, size=%d] for function %s@%s can not fit into specified register %s, size=%d, skipping.  DWARF DIE: %s"
								.formatted(getVarTypeName(diea), name.getName(), type.getName(),
									type.getLength(), dfunc.name.getName(), dfunc.address,
									reg.getName(), reg.getMinimumByteSize(), diea.getHexOffset()));
					return false;
				}
				setRegisterStorage(List.of(reg));
			}
			else if (exprEvaluator.getRawLastRegister() == -1 && res != 0) {
				// static global variable location
				setRamStorage(res);
			}
			else {
				Msg.error(this,
					"%s location error for function %s@%s, %s: %s, DWARF DIE: %s, unsupported location information."
							.formatted(getVarTypeName(diea), dfunc.name.getName(), dfunc.address,
								name.getName(),
								DWARFExpression.exprToString(location.getLocation(), diea),
								diea.getHexOffset()));
				return false;
			}

			return true;
		}
		catch (DWARFExpressionException | UnsupportedOperationException
				| IndexOutOfBoundsException ex) {
			importSummary.exprReadError++;
			return false;
		}
	}

	private String getVarTypeName(DIEAggregate diea) {
		return diea.getTag() == DWARFTag.DW_TAG_formal_parameter ? "Parameter" : "Variable";
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
			tmp.add(stackStorage);
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

	public Parameter asParameter(boolean includeStorageDetail, Program program)
			throws InvalidInputException {
		VariableStorage paramStorage = !isMissingStorage() && includeStorageDetail
				? getVariableStorage()
				: VariableStorage.UNASSIGNED_STORAGE;

		// try to allow ghidra to autoname param instead of using our autogenerated version
		String newName = name.isAnon() ? null : name.getName();

		ParameterImpl result =
			new ParameterImpl(newName, Parameter.UNASSIGNED_ORDINAL, type, paramStorage, true,
			program, SourceType.IMPORTED);
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
		VariableStorage storage = isVoidType()
				? VariableStorage.VOID_STORAGE
				: !isMissingStorage() && includeStorageDetail
						? getVariableStorage()
						: VariableStorage.UNASSIGNED_STORAGE;
		return new ReturnParameterImpl(type, storage, true, program.getGhidraProgram());
	}

	public void appendComment(String prefix, String comment, String sep) {
		if (comment == null || comment.isEmpty()) {
			comment = "";
		}
		else {
			comment += sep;
		}
		this.comment += prefix + comment;
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
