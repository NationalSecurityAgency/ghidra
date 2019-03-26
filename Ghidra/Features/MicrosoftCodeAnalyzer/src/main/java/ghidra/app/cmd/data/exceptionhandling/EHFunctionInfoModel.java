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
package ghidra.app.cmd.data.exceptionhandling;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAlignedPack4Structure;

import ghidra.app.cmd.data.AbstractCreateDataTypeModel;
import ghidra.app.cmd.data.EHDataTypeUtilities;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.exception.AssertException;

/**
 * Model for exception handling information about the Function Information data type and its 
 * associated exception handling data types.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class EHFunctionInfoModel extends AbstractCreateDataTypeModel {

	public static final int EH_MAGIC_NUMBER_V1 = 0x19930520;
	public static final int EH_MAGIC_NUMBER_V2 = 0x19930521;
	public static final int EH_MAGIC_NUMBER_V3 = 0x19930522;

	public static final String DATA_TYPE_NAME = "FuncInfo";
	private static final String STRUCTURE_NAME = STRUCT_PREFIX + DATA_TYPE_NAME;

	@SuppressWarnings("unused")
	private static final int MAGIC_NUMBER_ORDINAL = 0;
	private static final int MAX_STATE_ORDINAL = 1;
	private static final int UNWIND_MAP_ORDINAL = 2;
	private static final int TRY_BLOCK_COUNT_ORDINAL = 3;
	private static final int TRY_BLOCK_MAP_ORDINAL = 4;
	private static final int IP_TO_STATE_COUNT_ORDINAL = 5;
	private static final int IP_TO_STATE_MAP_ORDINAL = 6;

	private int magicNum;
	private int bbtFlags;
	private boolean isV1;
	private boolean isV2;
	private boolean isV3;
	private int dataTypeLength;

	private DataType dataType;
	private EHUnwindModel unwindModel;
	private EHTryBlockModel tryBlockModel;
	private EHIPToStateModel ipToStateModel;
	private EHESTypeListModel esTypeListModel;

	/**
	 * Creates the model for the exception handling FuncInfo data type.
	 * @param program the program
	 * @param address the address in the program for the FuncInfo.
	 */
	public EHFunctionInfoModel(Program program, Address address,
			DataValidationOptions validationOptions) {
		super(program, 1, address, validationOptions);
		init();
	}

	private void init() {

		int field0 = 0;
		try {
			field0 = getMemBuffer().getInt(0); // Can throw MemoryAccessException
		}
		catch (MemoryAccessException e) {
			// magicNum and bbtFlags remain 0 and isXX() variables remain false.
			return;
		}
		magicNum = field0 & 0x1fffffff;
		bbtFlags = field0 >>> 29;
		isV1 = (magicNum == EH_MAGIC_NUMBER_V1);
		isV2 = (magicNum == EH_MAGIC_NUMBER_V2);
		isV3 = (magicNum == EH_MAGIC_NUMBER_V3);

		dataTypeLength = doGetDataTypeLength();
	}

	@Override
	protected void checkDataType() throws InvalidDataTypeException {
		// Can't create the data type since don't know its size without a valid magic number.
		if (!hasValidMagicNum()) {
			throw new InvalidDataTypeException(
				getName() + " @ " + getAddress() + " doesn't have a valid magic number.");
		}
	}

	private String getStructureName() {
		return STRUCTURE_NAME;
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	/**
	 * Gets the version number of the data type.
	 * @return the version number or -1 if data type doesn't have valid magic number.
	 */
	public final int getVersionNumber() {
		if (isV3) {
			return 3;
		}
		if (isV2) {
			return 2;
		}
		if (isV1) {
			return 1;
		}
		return -1;
	}

	private boolean hasValidMagicNum() {
		return (isV1 || isV2 || isV3);
	}

	@Override
	protected int getDataTypeLength() {
		return dataTypeLength;
	}

	/**
	 * Determines the data type's length without actually creating the data type.
	 * @return the data type length or 0 if it can't be determined.
	 */
	private int doGetDataTypeLength() {
		if (!hasValidMagicNum()) {
			return 0;
		}
		DataTypeManager dataTypeManager = getProgram().getDataTypeManager();
		int intSize = new IntegerDataType(dataTypeManager).getLength();
		int uintSize = new UnsignedIntegerDataType(dataTypeManager).getLength();
		int ibo32Size = new ImageBaseOffset32DataType(dataTypeManager).getLength();
		int defaultPointerSize = getDefaultPointerSize();
		int size20;
		int additional21;
		int additional22 = intSize;
		if (isRelative()) {
			size20 = (uintSize * 3) + intSize + ibo32Size * 4;
			additional21 = ibo32Size;
		}
		else {
			size20 = (uintSize * 3) + intSize + (defaultPointerSize * 3);
			additional21 = defaultPointerSize;
		}
		if (isV1) {
			return size20;
		}
		else if (isV2) {
			return size20 + additional21;
		}
		else if (isV3) {
			return size20 + additional21 + additional22;
		}
		return 0;
	}

	/**
	 * Whether or not the memory at the address for this model appears to be a valid location for a 
	 * function information data type.
	 * @throws InvalidDataTypeException if this models location does not appear to be a FuncInfo 
	 * data type. The exception has a message indicating why it does not appear to be a valid 
	 * location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {
		if (!hasValidMagicNum()) {
			throw new InvalidDataTypeException(
				getName() + " data type must contain a valid magic number, but doesn't at " +
					getAddress() + ".");
		}
		// Does at least one of our maps have a count.
		if ((getUnwindCount() == 0) && (getTryBlockCount() == 0) && (getIPToStateCount() == 0)) {
			throw new InvalidDataTypeException(getName() + " data type doesn't have any map data.");
		}
		// Are the pointers or displacements to valid addresses.
		if (!isValidMap(getUnwindCount(), getUnwindMapAddress())) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " doesn't have a valid unwind map.");
		}
		if (!isValidMap(getTryBlockCount(), getTryBlockMapAddress())) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't have a valid try block map.");
		}
		if (!isValidMap(getIPToStateCount(), getIPToStateMapAddress())) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't have a valid IP to state map.");
		}
		if (isV2 || isV3) {
			Address esTypeListAddress;
			try {
				esTypeListAddress = getESTypeListAddress();
			}
			catch (UndefinedValueException e) {
				throw new AssertException(e); // Shouldn't occur unless bug in this class's code.
			}
			if (esTypeListAddress != null && !isValidMap(1, esTypeListAddress)) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't have a valid type list reference.");
			}
		}
	}

	/**
	 * Validate all the components that indicate count values for map entries.
	 * This method can be called to perform additional validation that count components appear to 
	 * have reasonable values that aren't more than the indicated maximum value.
	 * @param maxCount the maximum allowable count value
	 * @throws InvalidDataTypeException whose message indicates which count does not appear to 
	 * be valid.
	 */
	public void validateCounts(int maxCount) throws InvalidDataTypeException {
		checkValidity();
		checkEntryCount("unwind", getUnwindCount(), maxCount);
		checkEntryCount("try block", getTryBlockCount(), maxCount);
		checkEntryCount("IP to state", getIPToStateCount(), maxCount);
	}

	/**
	 * Validate all the locations (a relative or absolute address) indicated by components of 
	 * this FuncInfo data. All locations indicated by components are expected to be within
	 * the same block as the data for this model.
	 * @throws InvalidDataTypeException whose message indicates which referenced address does 
	 * not appear to be valid.
	 */
	public void validateLocationsInSameBlock() throws InvalidDataTypeException {
		checkValidity();
		Memory memory = getProgram().getMemory();
		Address funcInfoAddress = getAddress();
		MemoryBlock funcInfoBlock = memory.getBlock(funcInfoAddress);
		validateInSameBlock(getUnwindMapAddress(), "unwind map", memory, funcInfoBlock);
		validateInSameBlock(getTryBlockMapAddress(), "try block map", memory, funcInfoBlock);
		validateInSameBlock(getIPToStateMapAddress(), "IP to state map", memory, funcInfoBlock);
		try {
			validateInSameBlock(getESTypeListAddress(), "ES type list", memory, funcInfoBlock);
		}
		catch (UndefinedValueException e) {
			// It's okay if the structure doesn't include an ES Type List component.
		}
	}

	private void validateInSameBlock(Address referenceAddress, String componentName, Memory memory,
			MemoryBlock funcInfoBlock) throws InvalidDataTypeException {
		if (referenceAddress != null) {
			MemoryBlock block = memory.getBlock(referenceAddress);
			if (funcInfoBlock != block) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" has a " + componentName +
					" component that refers to an address that is in a different memory block.");
			}
		}
	}

	/**
	 * If this is a valid FuncInfo location, the correct FuncInfo structure is returned.
	 * Otherwise this returns a null.
	 * @return the FuncInfo structure or null.
	 */
	@Override
	public DataType getDataType() {
		if (dataType == null) {
			dataType = doGetDataType();
		}
		return dataType;
	}

	/**
	 * If this is a valid FuncInfo location, the correct FuncInfo structure is returned.
	 * Otherwise this returns a null.
	 * @return the FuncInfo structure or null.
	 */
	private DataType doGetDataType() {
		if (!hasValidMagicNum()) {
			return null;
		}
		Program program = getProgram();
		if (dataType == null) {
			boolean isRelative = isRelative();
			DataTypeManager dataTypeManager = program.getDataTypeManager();
			CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
			StructureDataType struct =
				getAlignedPack4Structure(dataTypeManager, categoryPath, getStructureName());

			// Add the components.
			DataType compDt;

			/* comps[0] */
			// Magic number is low order 29 bits; bbtFlags is 3 high order bits.
			compDt = new UnsignedIntegerDataType(dataTypeManager);
			struct.add(compDt, "magicNumber_and_bbtFlags", null);

			/* comps[1] */
			compDt = new TypedefDataType(new CategoryPath("/ehdata.h"), "__ehstate_t",
				new IntegerDataType(dataTypeManager), dataTypeManager);
			struct.add(compDt, "maxState", null);

			/* comps[2] */
			if (isRelative) {
				compDt = new ImageBaseOffset32DataType(dataTypeManager);
				struct.add(compDt, "dispUnwindMap", null);
			}
			else {
				compDt = new PointerDataType(EHUnwindModel.getDataType(program), dataTypeManager);
				struct.add(compDt, "pUnwindMap", null);
			}

			/* comps[3] */
			compDt = new UnsignedIntegerDataType(dataTypeManager);
			struct.add(compDt, "nTryBlocks", null);

			/* comps[4] */
			if (isRelative) {
				compDt = new ImageBaseOffset32DataType(dataTypeManager);
				struct.add(compDt, "dispTryBlockMap", null);
			}
			else {
				compDt = new PointerDataType(EHTryBlockModel.getDataType(program), dataTypeManager);
				struct.add(compDt, "pTryBlockMap", null);
			}

			/* comps[5] */
			compDt = new UnsignedIntegerDataType(dataTypeManager);
			struct.add(compDt, "nIPMapEntries", null);

			/* comps[6] */
			if (isRelative) {
				compDt = new ImageBaseOffset32DataType(dataTypeManager);
				struct.add(compDt, "dispIPToStateMap", null);
			}
			else {
				compDt = new PointerDataType(new VoidDataType(dataTypeManager), dataTypeManager);
				struct.add(compDt, "pIPToStateMap", null);
			}

			if (isRelative) { /* comps[7] */
				compDt = new IntegerDataType(dataTypeManager);
				struct.add(compDt, "dispUnwindHelp", null);
			}

			if (isV2 || isV3) {
				if (isRelative) { /* comps[8] */
					compDt = new ImageBaseOffset32DataType(dataTypeManager);
					struct.add(compDt, "dispESTypeList", null);
				}
				else { /* comps[7] */
					compDt = new PointerDataType(EHESTypeListModel.getDataType(program),
						dataTypeManager);
					struct.add(compDt, "pESTypeList", null);
				}
			}

			if (isV3) { /* comps[8 or 9] */
				compDt = new IntegerDataType(dataTypeManager);
				struct.add(compDt, "EHFlags", null);
			}

			TypedefDataType typedef =
				new TypedefDataType(categoryPath, getName(), struct, dataTypeManager);

			dataType = typedef;
		}

		return MSDataTypeUtils.getMatchingDataType(program, dataType);
	}

	/**
	 * Gets the value of the magic number.
	 * @return the magic number or 0.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getMagicNumber() throws InvalidDataTypeException {
		checkValidity();
		return magicNum;
	}

	/**
	 * Gets the value of the bbt flags.
	 * @return the bbt flags.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getBbtFlags() throws InvalidDataTypeException {
		checkValidity();
		return bbtFlags;
	}

	/**
	 * Gets the unwind model for the function info.
	 * @return the unwind model, which may be invalid.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public EHUnwindModel getUnwindModel() throws InvalidDataTypeException {
		checkValidity();
		if (unwindModel == null) {
			unwindModel = new EHUnwindModel(getProgram(), getUnwindCount(), getUnwindMapAddress(),
				validationOptions);
		}
		return unwindModel;
	}

	/**
	 * Gets the number of unwind map entries for this function information data.
	 * @return number of unwind map entries
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getUnwindCount() throws InvalidDataTypeException {
		checkValidity();
		// component 1 is number of unwind records
		return EHDataTypeUtilities.getCount(getDataType(), MAX_STATE_ORDINAL, getMemBuffer());
	}

	/**
	 * Gets the address of the unwind map, if there is one. Otherwise, this returns null.
	 * @return the address of the unwind map or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getUnwindMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 2 is UnwindMap pointer or displacement.
		Address mapAddress =
			EHDataTypeUtilities.getAddress(getDataType(), UNWIND_MAP_ORDINAL, getMemBuffer());
		return getAdjustedAddress(mapAddress, getUnwindCount());
	}

	/**
	 * Gets the address of the component containing the address of the unwind map, if there is one. 
	 * Otherwise, this returns null.
	 * @return the address of the component with the address of the unwind map or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getComponentAddressOfUnwindMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 2 is UnwindMap pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(getDataType(), UNWIND_MAP_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the try block model for the function info.
	 * @return the try block model, which may be invalid.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public EHTryBlockModel getTryBlockModel() throws InvalidDataTypeException {
		checkValidity();
		if (tryBlockModel == null) {
			tryBlockModel = new EHTryBlockModel(getProgram(), getTryBlockCount(),
				getTryBlockMapAddress(), validationOptions);
		}
		return tryBlockModel;
	}

	/**
	 * Gets the number of try block map entries for this function information data.
	 * @return number of try block map entries
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getTryBlockCount() throws InvalidDataTypeException {
		checkValidity();
		// component 3 is number of try block records
		return EHDataTypeUtilities.getCount(getDataType(), TRY_BLOCK_COUNT_ORDINAL, getMemBuffer());
	}

	/**
	 * Gets the address of the try block map, if there is one. Otherwise, this returns null.
	 * @return the address of the try block map or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getTryBlockMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 4 is TryBlockMap pointer or displacement.
		Address mapAddress =
			EHDataTypeUtilities.getAddress(getDataType(), TRY_BLOCK_MAP_ORDINAL, getMemBuffer());
		return getAdjustedAddress(mapAddress, getTryBlockCount());
	}

	/**
	 * Gets the address of the component containing the try block map address, if there is one. 
	 * Otherwise, this returns null.
	 * @return the address of the component with the try block map address or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getComponentAddressOfTryBlockMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 4 is TryBlockMap pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(getDataType(), TRY_BLOCK_MAP_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the IP to state model for the function info.
	 * @return the IP to state model, which may be invalid.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public EHIPToStateModel getIPToStateModel() throws InvalidDataTypeException {
		checkValidity();
		if (ipToStateModel == null) {
			ipToStateModel = new EHIPToStateModel(getProgram(), getIPToStateCount(),
				getIPToStateMapAddress(), validationOptions);
		}
		return ipToStateModel;
	}

	/**
	 * Gets the number of IP to state map entries for this function information data.
	 * @return number of IP to state map entries
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getIPToStateCount() throws InvalidDataTypeException {
		checkValidity();
		// component 5 is number of IP to State records
		return EHDataTypeUtilities.getCount(getDataType(), IP_TO_STATE_COUNT_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the address of the IP to state map, if there is one. Otherwise, this returns null.
	 * @return the address of the IP to state map or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getIPToStateMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 6 is IPToStateMap pointer or displacement.
		Address mapAddress =
			EHDataTypeUtilities.getAddress(getDataType(), IP_TO_STATE_MAP_ORDINAL, getMemBuffer());
		return getAdjustedAddress(mapAddress, getIPToStateCount());
	}

	/**
	 * Gets the address of the component containing the IP to state map address, if there is one. 
	 * Otherwise, this returns null.
	 * @return the address of the component with the IP to state map address or null.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getComponentAddressOfIPToStateMapAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 6 is IPToStateMap pointer or displacement.
		return EHDataTypeUtilities.getComponentAddress(getDataType(), IP_TO_STATE_MAP_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the address of the unwind help, if it exists. Otherwise, this returns null.
	 * @return the address of the unwind help or null.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the UnwindHelp displacement.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getUnwindHelpDisplacement()
			throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (isRelative()) {
			// component 7 is UnwindHelp pointer or displacement.
			return EHDataTypeUtilities.getCount(getDataType(), 7, getMemBuffer());
		}
		throw new UndefinedValueException(
			"No UnwindHelp displacement, since it isn't defined for this program.");
	}

	/**
	 * Gets the address of the component containing the unwind help address, if there is one. 
	 * Otherwise, this returns null.
	 * @return the address of the component with the unwind help address or null.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the UnwindHelp address.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getComponentAddressOfUnwindHelpAddress()
			throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (isRelative()) {
			// component 7 is UnwindHelp pointer or displacement.
			return EHDataTypeUtilities.getComponentAddress(getDataType(), 7, getMemBuffer());
		}
		throw new UndefinedValueException(
			"No UnwindHelp address, since it isn't defined for this program.");
	}

	/**
	 * Gets the ESTypeList model for the function info.
	 * @return the ESTypeList model, which may be invalid.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the ESTypeList address.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public EHESTypeListModel getESTypeListModel()
			throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (esTypeListModel == null) {
			Address esTypeListAddress = getESTypeListAddress();
			if (esTypeListAddress == null) {
				throw new UndefinedValueException(DATA_TYPE_NAME + " at " + getAddress() +
					" doesn't specify an " + EHESTypeListModel.DATA_TYPE_NAME + " address.");
			}
			esTypeListModel =
				new EHESTypeListModel(getProgram(), esTypeListAddress, validationOptions);
		}
		return esTypeListModel;
	}

	/**
	 * Gets the address of the ES type list, if there is one. Otherwise, this returns null.
	 * @return the address of the ES type list or null.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the ESTypeList address.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getESTypeListAddress() throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (isV2 || isV3) {
			// component 7 or 8 is ESTypeList pointer or displacement.
			Address refAddress = EHDataTypeUtilities.getAddress(getDataType(),
				(isRelative() ? 8 : 7), getMemBuffer());
			return getAdjustedAddress(refAddress, 0);
		}
		throw new UndefinedValueException(
			"No ESTypeList address, since not a version 2 or 3 FuncInfo structure.");
	}

	/**
	 * Gets the address of the component containing the ES type list address, if there is one. 
	 * Otherwise, this returns null.
	 * @return the address of the component with the ES type list address or null.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the ESTypeList address.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public Address getComponentAddressOfESTypeListAddress()
			throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (isV2 || isV3) {
			// component 7 or 8 is ESTypeList pointer or displacement.
			return EHDataTypeUtilities.getComponentAddress(getDataType(), (isRelative() ? 8 : 7),
				getMemBuffer());
		}
		throw new UndefinedValueException(
			"No ESTypeList address, since not a version 2 or 3 FuncInfo structure.");
	}

	/**
	 * Gets the value of the EH flags.
	 * @return the EH flags.
	 * @throws UndefinedValueException if this FuncInfo doesn't specify the EH Flags.
	 * @throws InvalidDataTypeException if valid FuncInfo data can't be created at the model's address.
	 */
	public int getEHFlags() throws UndefinedValueException, InvalidDataTypeException {
		checkValidity();
		if (isV3) {
			// component 8 or 9 is EH flags.
			return EHDataTypeUtilities.getCount(getDataType(), (isRelative() ? 9 : 8),
				getMemBuffer());
		}
		throw new UndefinedValueException("No EH Flags, since not a version 3 FuncInfo structure.");
	}

	/**
	 * Gets the TryBlockMapEntry model associated with this FuncInfo.
	 * @return the TryBlockMapEntry model or null.
	 */
	public EHTryBlockModel getEHTryBlockModel() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return tryBlockModel;
	}

	/**
	 * Gets the UnwindMapEntry model associated with this FuncInfo.
	 * @return the UnwindMapEntry model or null.
	 */
	public EHUnwindModel getEHUnwindModel() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return unwindModel;
	}

	/**
	 * Gets the IpToStateMapEntry model associated with this FuncInfo.
	 * @return the IpToStateMapEntry model or null.
	 */
	public EHIPToStateModel getEHIPToStateModel() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return ipToStateModel;
	}

	/**
	 * Gets the ESTypeList model associated with this FuncInfo.
	 * @return the ESTypeList model or null.
	 */
	public EHESTypeListModel getEHESTypeListModel() {
		try {
			checkValidity();
		}
		catch (InvalidDataTypeException e) {
			return null;
		}
		return esTypeListModel;
	}

	/**
	 * Gets a string that provides information about the function information for this object's
	 * program and address.
	 * @return the function information
	 */
	@Override
	public String toString() {
		StringBuffer buffer = new StringBuffer();
		buffer.append("EHFunctionInfo" + NEW_LINE);
		buffer.append(INDENT + "Program: " + getProgram().getDomainFile().getPathname() + NEW_LINE);
		buffer.append(INDENT + "Address: " + getAddress().toString(true) + NEW_LINE);
		buffer.append(INDENT + "fitsInSingleMemoryBlock: " + fitsInSingleMemoryBlock() + NEW_LINE);
		buffer.append(INDENT + "isRelative: " + isRelative() + NEW_LINE);
		buffer.append(INDENT + "defaultPointerSize: " + getDefaultPointerSize() + NEW_LINE);
		buffer.append(INDENT + "magicNum: " + "0x" + Long.toHexString(magicNum) + NEW_LINE);
		buffer.append(INDENT + "bbtFlags: " + "0x" + Long.toHexString(bbtFlags) + NEW_LINE);
		DataType dt = getDataType();
		if (dt != null) {
			buffer.append(NEW_LINE + dt.toString() + NEW_LINE);
			if (dt instanceof TypeDef) {
				DataType baseDataType = ((TypeDef) dt).getBaseDataType();
				buffer.append(NEW_LINE + baseDataType.toString() + NEW_LINE);
			}
		}
		return buffer.toString();
	}
}
