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

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.DW_AT_external;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.DW_TAG_formal_parameter;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import ghidra.app.cmd.comments.AppendCommentCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.bin.format.dwarf4.DIEAggregate;
import ghidra.app.util.bin.format.dwarf4.DWARFLocation;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFBlobAttribute;
import ghidra.app.util.bin.format.dwarf4.attribs.DWARFNumericAttribute;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpression;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionEvaluator;
import ghidra.app.util.bin.format.dwarf4.expression.DWARFExpressionException;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunctionImporter.DWARFFunction;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FactoryDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;

public abstract class DWARFVariableVisitor {

	protected final DWARFProgram prog;
	protected final Program currentProgram;
	protected final DWARFDataTypeManager dwarfDTM;
	protected ProgramModule rootModule;
	protected Set<Long> processedOffsets = new HashSet<>();
	private Set<Address> variablesProcesesed = new HashSet<>();
	protected DWARFImportSummary importSummary;

	protected DWARFFunction populateDWARFFunc(DIEAggregate diea) throws IOException {
		DWARFFunction dfunc = new DWARFFunction(prog.getName(diea));
		dfunc.namespace = dfunc.dni.getParentNamespace(currentProgram);

		Number lowPC = diea.getLowPC(0);
		dfunc.address = toAddr(lowPC);
		dfunc.highAddress =
			diea.hasAttribute(DWARFAttribute.DW_AT_high_pc) ? toAddr(diea.getHighPC()) : null;
		return dfunc;

	}

	/**
	 * Get the location that corresponds to the entry point of the function If
	 * there is only a single location, assume it applies to whole function
	 *
	 * @param locList
	 * @param funcAddr
	 * @return the byte array corresponding to the location expression
	 */
	protected static DWARFLocation getTopLocation(List<DWARFLocation> locList, long funcAddr) {
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

	protected boolean shouldProcess(DIEAggregate diea) {
		if (processedOffsets.contains(diea.getOffset())) {
			return false;
		}
		processedOffsets.add(diea.getOffset());
		return true;
	}

	abstract protected Optional<Long> resolveStackOffset(long off, DWARFLocation loc,
			DWARFFunction dfunc, boolean validRange, Optional<Address> block_start);

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
	protected DWARFVariable processVariable(DIEAggregate diea, DWARFFunction dfunc,
			Address lexicalStart, long firstUseAddr)
			throws IOException, InvalidInputException {

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

		var valid_range = diea.hasAttribute(DWARFAttribute.DW_AT_location) &&
			diea.getAttribute(DWARFAttribute.DW_AT_location) instanceof DWARFNumericAttribute;

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
			var ajustedoff = this.resolveStackOffset(res, topLocation, dfunc, valid_range,
				Optional.ofNullable(lexicalStart));
			if (!ajustedoff.isPresent()) {
				dfunc.localVarErrors = true;
				return null;
			}

			dvar.offset = ajustedoff.get();
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
					if (diea.getTag() != DW_TAG_formal_parameter) {
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

			boolean external = diea.getBool(DW_AT_external, false);

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
	 * Appends a comment at the specified address
	 * @param address the address to set the PRE comment
	 * @param commentType ie. CodeUnit.PRE_COMMENT
	 * @param comment the PRE comment
	 * @param sep the characters to use to separate existing comments
	 * @return true if the comment was successfully set
	 */
	protected boolean appendComment(Address address, int commentType, String comment, String sep) {
		AppendCommentCmd cmd = new AppendCommentCmd(address, commentType, comment, sep);
		return cmd.applyTo(currentProgram);
	}

	protected final Address toAddr(Number offset) {
		return currentProgram.getAddressFactory()
				.getDefaultAddressSpace()
				.getAddress(
					offset.longValue(), true);
	}

	/**
	 * Set external entry point.  If declared external add as entry pointer, otherwise
	 * clear as entry point if previously addeds.
	 * @param external true if declared external and false otherwise
	 * @param address address of the entry point
	 */
	protected void setExternalEntryPoint(boolean external, Address address) {
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
			Data result = DataUtilities.createData(currentProgram, address, dataType, -1,
				ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			variablesProcesesed.add(address);
			if (eolComment != null) {
				appendComment(address, CodeUnit.EOL_COMMENT, eolComment, "\n");
			}
			return result;
		}
		catch (CodeUnitInsertionException e) {
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
		 * Holds values necessary to create a new variable / parameter.
		 */
	public static class DWARFVariable {
		public DWARFNameInfo dni;
		public DataType type;
		public long offset;// Offset on stack or firstuseoffset if this is a register
		public boolean isStackOffset;// true if offset represents stack offset
		public long lexicalOffset;
		public Register reg;
	}

	/**
	 * Move an address range into a fragment.
	 * @param name name of the fragment
	 * @param start start address of the fragment
	 * @param end end address of the fragment
	 * @param fileName file name of module
	 */
	protected void moveIntoFragment(String name, Address start, Address end, String fileName) {
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
	 * 
	 * @param dvar the dwarf variable to create a Ghidra var for
	 * @return a Ghidra variable matching the storage and type declared by the dwarf var
	 * @throws InvalidInputException
	 */
	protected Variable buildVariable(DWARFVariable dvar) throws InvalidInputException {
		Varnode[] vnarray = buildVarnodes(dvar);
		VariableStorage storage = new VariableStorage(currentProgram, vnarray);
		int firstUseOffset = 0;
		if ((dvar.reg != null) && (dvar.offset != -1)) {
			firstUseOffset = (int) dvar.offset;
		}
		return new LocalVariableImpl(dvar.dni.getName(), firstUseOffset, dvar.type, storage,
			currentProgram);
	}

	protected Varnode[] buildVarnodes(DWARFVariable dvar) {
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

	public DWARFVariableVisitor(DWARFProgram prog, Program currentProgram,
			DWARFDataTypeManager dwarfDTM) {
		super();
		this.prog = prog;
		this.currentProgram = currentProgram;
		this.dwarfDTM = dwarfDTM;
	}

}