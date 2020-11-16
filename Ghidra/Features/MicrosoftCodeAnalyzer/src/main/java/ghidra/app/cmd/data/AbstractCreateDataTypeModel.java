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
package ghidra.app.cmd.data;

import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

/**
 * Abstract model for information about a windows data type and its associated structure, 
 * which can be used to create and validate it in a program.
 */
public abstract class AbstractCreateDataTypeModel {

	protected static final String STRUCT_PREFIX = "_s_";
	protected static String CATEGORY_PATH = "/";
	protected static final String NEW_LINE = "\n";
	protected static final String INDENT = "    ";

	private Program program;
	private int count;
	private Address address;
	private MemBuffer memBuffer;
	private boolean dataTypeAlreadyBasedOnCount = false;

	private boolean isValidAddress;
	private boolean isInitializedAddress;
	private boolean isExecutableAddress;
	private boolean isLoadedAndInitialized;
	private boolean is64Bit;
	private boolean isRelative;
	private int defaultPointerSize;
	private DataTypeManager dataTypeManager;
	protected Address imageBaseAddress;
	private boolean alreadyValidated;
	private boolean isValid;
	private String exceptionMessage;
	protected DataValidationOptions validationOptions;

	/**
	 * Constructor for the abstract create data type model. This constructor assumes 
	 * that only a single data type will be created at the indicated address in the program.
	 * @param program the program where the data type would be created.
	 * @param address the address where the data type would be created.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public AbstractCreateDataTypeModel(Program program, Address address,
			DataValidationOptions validationOptions) {
		this(program, 1, address, validationOptions);
	}

	/**
	 * Constructor for the abstract create data type model. This constructor expects
	 * to create <code>count</code> number of data types at the indicated address in the program.
	 * If more than one data type is being created, they will be in an array data type.
	 * @param program the program where the data type would be created.
	 * @param count the number of data types to create.
	 * @param address the address where the data type would be created.
	 * @param validationOptions options indicating how to validate the data type at the indicated 
	 * address.
	 */
	public AbstractCreateDataTypeModel(Program program, int count, Address address,
			DataValidationOptions validationOptions) {
		this.program = program;
		this.count = count;
		if (address == Address.NO_ADDRESS) {
			throw new IllegalArgumentException(
				"Can't create a " + getName() + " exception handling model at NO_ADDRESS.");
		}
		if (address == null) {
			throw new IllegalArgumentException("Null isn't a valid address for creating a " +
				getName() + " exception handling model.");
		}
		this.address = address;
		this.validationOptions = validationOptions;
		init();
	}

	private void init() {
		// Many 64 bit data types use relative values (ibo32), while 32 bit use absolute (pointers).
		is64Bit = MSDataTypeUtils.is64Bit(program);
		isRelative = isRelative(program);
		defaultPointerSize = program.getDefaultPointerSize();
		Memory memory = program.getMemory();
		isValidAddress = memory.contains(address);
		MemoryBlock block = memory.getBlock(address);
		isInitializedAddress = (block != null) ? block.isInitialized() : false;
		isExecutableAddress = (block != null) ? block.isExecute() : false;
		AddressSetView loadedAndInitializedSet = memory.getLoadedAndInitializedAddressSet();
		isLoadedAndInitialized = loadedAndInitializedSet.contains(address);
		memBuffer = new DumbMemBufferImpl(memory, address);
		dataTypeManager = program.getDataTypeManager();
		imageBaseAddress = getProgram().getImageBase();
	}

	/**
	 * Determine if the program in this model is for windows.
	 * @return true if the program is a windows program.
	 */
	final protected boolean isWindows() {
		CompilerSpecID compilerSpecID = program.getCompilerSpec().getCompilerSpecID();
		String compilerIdString = compilerSpecID.getIdAsString();
		String compilerString = program.getCompiler();
		return ("windows".equals(compilerIdString) || "clangwindows".equals(compilerIdString)) &&
			program.getExecutableFormat().equals(PeLoader.PE_NAME) &&
			(compilerString.equals(CompilerEnum.VisualStudio.toString()) ||
				compilerString.equals(CompilerEnum.Clang.toString()));
	}

	/**
	 * Determine if the address for this model is actually in the program.
	 * @return true if the address for the data type is valid.
	 */
	protected final boolean isValidAddress() {
		return isValidAddress;
	}

	/**
	 * Determine if the address for this model is within an initialized block in the program.
	 * @return true if the address for the data type is initialized.
	 */
	protected final boolean isInitializedAddress() {
		return isInitializedAddress;
	}

	/**
	 * Determine if the address for this model is within an executable block in the program.
	 * @return true if the address for the data type is executable.
	 */
	protected final boolean isExecutableAddress() {
		return isExecutableAddress;
	}

	/**
	 * Determine if the address for this model is within a loaded and initialized block in the program.
	 * @return true if the address for the data type is loaded and initialized.
	 */
	public final boolean isLoadedAndInitializedAddress() {
		return isLoadedAndInitialized;
	}

	/**
	 * Determine if this model is for a 64 bit program.
	 * @return true if the model's program is 64 bit.
	 */
	protected final boolean is64Bit() {
		return is64Bit;
	}

	/**
	 * Determine if the components in this model's data type use relative offsets or pointers.
	 * @param program the program which will contain this model's data type. 
	 * @return true if the data type uses relative offsets.
	 */
	protected static boolean isRelative(Program program) {
		return MSDataTypeUtils.is64Bit(program); // May need more here later.
	}

	/**
	 * Determine if the components in the data type use relative offsets or pointers.
	 * @return true if the data type uses relative offsets.
	 */
	protected final boolean isRelative() {
		return isRelative;
	}

	/**
	 * Determine the program's default pointer size.
	 * @return the default pointer size.
	 */
	protected final int getDefaultPointerSize() {
		return defaultPointerSize;
	}

	/**
	 * Gets the program's data type manager.
	 * @return the data type manager.
	 */
	protected final DataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	/**
	 * Gets the program's memory buffer for this model based on the model's address.
	 * @return the MemBuffer.
	 */
	protected final MemBuffer getMemBuffer() {
		return memBuffer;
	}

	/**
	 * Gets the length of this model's data type.
	 * @return the data type length or 0 if the length can't be determined.
	 */
	protected abstract int getDataTypeLength();

	/**
	 *  Determines if the data type will fit in a single memory block in the program.
	 * @return true if the data type fits in a single block.
	 */
	protected boolean fitsInSingleMemoryBlock() {
		int dataTypeLength = getDataTypeLength();
		if (dataTypeLength < 0) {
			return false;
		}
		try {
			long totalSize = dataTypeLength * count;
			Address start = getAddress();
			Address end = start.add(totalSize - 1);
			Memory memory = getProgram().getMemory();
			MemoryBlock startBlock = memory.getBlock(start);
			return startBlock != null && startBlock.contains(end);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Gets the alignment for this model's data type.
	 * @return the data type's alignment
	 */
	protected int getAlignment() {
		DataType dt = getDataType();
		if (dt != null) {
			return dt.getAlignment();
		}
		return 4; // Default to 4 byte aligned.
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of the indicated data type.
	 * @throws InvalidDataTypeException if this model's location doesn't appear to be valid for
	 * a group of entries of the indicated data type. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	public void validate() throws InvalidDataTypeException {
		if (alreadyValidated) {
			if (exceptionMessage != null) {
				throw new InvalidDataTypeException(exceptionMessage);
			}
			return; // It was already determined to be valid.
		}

		try {
			alreadyValidated = true;
			isValid = true;
			doValidate();
			validateModelSpecificInfo();
		}
		catch (InvalidDataTypeException e) {
			isValid = false;
			exceptionMessage = e.getMessage();
			throw e;
		}
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of the indicated data type. Models that extend AbstractCreateDataTypeModel 
	 * should override this method in order to check model specific information to determine that 
	 * it's data type will be valid at the address.
	 * <br>Note: This method will be called by validate().
	 * <br>Important: None of the code in this method or in anything it calls should call the 
	 * model's checkValidity() method.
	 * @throws InvalidDataTypeException if this model's location doesn't appear to be valid for
	 * a group of entries of the indicated data type. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	protected abstract void validateModelSpecificInfo() throws InvalidDataTypeException;

	/**
	 * Performs validation of the parts that are common to all models that extend this class.
	 * @throws InvalidDataTypeException if the model isn't valid for the associated program and 
	 * address. The message in the exception indicates why the model isn't valid.
	 */
	private void doValidate() throws InvalidDataTypeException {
		if (!isWindows()) {
			throw new InvalidDataTypeException(
				getName() + " data type model is only valid for Visual Studio windows PE.");
		}
		if (!isValidAddress()) {
			throw new InvalidDataTypeException(
				getName() + " data type isn't at a valid address " + getAddress() + ".");
		}
//		if (!isInitializedAddress()) {
//			throw new InvalidDataTypeException(
//				getName() + " data type isn't on an initialized address " + getAddress() + ".");
//		}
		if (!isLoadedAndInitializedAddress()) {
			throw new InvalidDataTypeException(getName() +
				" data type isn't on a loaded and initialized address " + getAddress() + ".");
		}
		checkDataType();
		if (!fitsInSingleMemoryBlock()) {
			throw new InvalidDataTypeException(
				getName() + " data type doesn't fit in a single memory block when placed at " +
					getAddress() + ".");
		}
		if (getAddress().getOffset() % getAlignment() != 0) {
			throw new InvalidDataTypeException(
				getName() + " data type is not properly aligned at " + getAddress() + ".");
		}

		Listing listing = program.getListing();
		Address startAddress = address;

		int dtLength = getDataTypeLength();
		long numBytes = dtLength * count;
		if (numBytes <= 0) {
			throw new InvalidDataTypeException(
				"Cannot determine length for " + getName() + " data type at " + getAddress() + ".");
		}
		Address endAddress = address.add(numBytes - 1);

		if (!getValidationOptions().shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			throw new InvalidDataTypeException("Instructions are in the way of " + count + " " +
				getName() + " data type(s) at " + getAddress() + ".");
		}

		if (!getValidationOptions().shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			throw new InvalidDataTypeException("Defined data is in the way of " + count + " " +
				getName() + " data type(s) at " + getAddress() + ".");
		}

	}

	/**
	 * Your model must override this method if the model can't always determine the exact
	 * composition of the exception handling data structure and its size.
	 * @throws InvalidDataTypeException if the model can't determine the data type and its size
	 * when placed on memory at the model's address in the program. The exception should contain 
	 * a message that indicates why it can't determine the composition of the data type or its size.
	 */
	protected void checkDataType() throws InvalidDataTypeException {
		// Override this method if the model can't create the data type or doesn't know its size.
	}

	/**
	 * This method can be called by a model's get methods to validate the model before trying 
	 * to retrieve a particular piece of information
	 * <br>Important: This method must not be called by any methods that are called (possibly 
	 * indirectly) by the model's validateModelSpecificInfo() method.
	 * @throws InvalidDataTypeException if the model's data type isn't valid at the associated
	 * address in the program.
	 */
	protected void checkValidity() throws InvalidDataTypeException {
		if (!isValid()) {
			throw new InvalidDataTypeException(getName() + " data type isn't valid at " +
				getAddress() + " in " + getProgram() + ".");
		}
	}

	/**
	 * This method can be called by a model's methods to validate the model before trying 
	 * to retrieve a particular piece of information. It also validates that the ordinal value 
	 * doesn't exceed the count for the model.
	 * <br>Important: This method must not be called by any methods that are called (possibly 
	 * indirectly) by the model's validateModelSpecificInfo() method.
	 * @param ordinal the ordinal indicating which one of the multiple copies of the data type
	 * to be laid down at the address.
	 * @throws InvalidDataTypeException if the model's data type isn't valid at the associated
	 * address in the program.
	 */
	protected void checkValidity(int ordinal) throws InvalidDataTypeException {
		checkValidity();
		if (ordinal < 0 || ordinal >= getCount()) {
			throw new IllegalArgumentException(ordinal + " is not a valid ordinal for " +
				getName() + " data type at " + getAddress() + " in " + getProgram() + ".");
		}
	}

	private boolean isValid() {
		if (!alreadyValidated) {
			try {
				validate();
			}
			catch (InvalidDataTypeException e) {
				return false;
			}
		}
		return isValid;
	}

	/**
	 * Gets the program that is associated with this model. The program is where the data type
	 * will be validated/created.
	 * @return the program
	 */
	public final Program getProgram() {
		return program;
	}

	/**
	 * Gets a count indicating the number of this data type that should occur in the program at 
	 * the specified address.
	 * @return the count
	 */
	public final int getCount() {
		return count;
	}

	/**
	 * The address in the program where this model should begin validating or overlaying the 
	 * data type for this model.
	 * @return the address
	 */
	public final Address getAddress() {
		return address;
	}

	/**
	 * Converts the indicated address to null whenever there are no entries as indicated
	 * by numEntries and the filler address is as expected.
	 * <br>
	 * Map addresses are extracted from a component in a structure in memory. 
	 * This method returns null when the associated number of expected map entries in the 
	 * table is 0 and the value for no entries is used for the address. Otherwise, either 
	 * the image base offset or a zero address could get used when the address isn't actually 
	 * relevant.
	 * 
	 * @param mapAddress address where the map data types are expected.
	 * @param numEntries the number of expected map entries.
	 * @return the mapAddress or null when appropriate to indicate no valid address.
	 */
	protected Address getAdjustedAddress(Address mapAddress, int numEntries) {
		if (mapAddress == null) {
			return null; // null address indicates the map is not used.
		}
		if (numEntries == 0) {
			if (isRelative) {
				if (mapAddress.equals(imageBaseAddress)) {
					return null; // null address indicates the map is not used.
				}
			}
			else {
				if (mapAddress.getOffset() == 0) { // zero address
					return null; // null address indicates the map is not used.
				}
			}
		}
		return mapAddress;
	}

	/**
	 * Gets the last address within the data type for this model.
	 * @return the end address or null.
	 * @throws AddressOutOfBoundsException if data type wont fit in memory.
	 * @throws InvalidDataTypeException if length of data type can't be determined.
	 */
	Address getEndAddress() throws InvalidDataTypeException {
		int dtLength = getDataTypeLength();
		if (dtLength == 0) {
			throw new InvalidDataTypeException(
				"Couldn't determine data type length for " + getName() + ".");
		}
		try {
			return address.add(dtLength - 1);
		}
		catch (AddressOutOfBoundsException e) {
			throw new InvalidDataTypeException(
				getName() + " data type doesn't fit in memory at " + getAddress() + ".");
		}
	}

	/**
	 * Gets the name of the data type validated and created by this model.
	 * @return the data type's name.
	 */
	public abstract String getName();

	/**
	 * Gets the data type for this model.
	 * @return the data type that is validated and created by this model.
	 */
	public abstract DataType getDataType();

	/**
	 * Determines if the map information appears valid based on the number of entries and the 
	 * address of the map. zero can be a valid number of entries.
	 * @param numEntries the number of entries in the map.
	 * @param mapAddress the address of the map.
	 * @return true if the map values appear to be valid.
	 */
	protected boolean isValidMap(int numEntries, Address mapAddress) {
		if (numEntries == 0) {
			if (mapAddress == null) {
				return true; // null address indicates the map is not used, which is a valid state.
			}
			if (isRelative) {
				return imageBaseAddress.equals(mapAddress);
			}
			return false;
		}
		else if (mapAddress == null) {
			return false;
		}
		Memory memory = getProgram().getMemory();
		return memory.getLoadedAndInitializedAddressSet().contains(mapAddress);
	}

	/**
	 * Whether or not the memory has any instructions defined in the area from the indicated 
	 * address up to the size of the data type for this model.
	 * @return true if there are any instructions where the data type is being placed.
	 * @throws InvalidDataTypeException if data type's expected bytes can't be checked.
	 */
	public boolean isBlockedByInstructions() throws InvalidDataTypeException {
		// Is there enough memory for data type?
		Address start = getAddress();
		Address end = getEndAddress();
		AddressSet addrSet = new AddressSet(start, end);
		// Are there any instructions in the way?
		Listing listing = program.getListing();
		Instruction inst = listing.getInstructionContaining(start);
		if (inst != null) {
			return true;
		}
		InstructionIterator instIter = listing.getInstructions(addrSet, true);
		if (instIter.hasNext()) {
			return true;
		}
		return false;
	}

	/**
	 * Gets the MemBuffer for the indicated data type in the array when the model has a count
	 * that is greater than 1.
	 * @param ordinal 0-based ordinal indicating which data types memory is desired.
	 * @param dt the data type handled by this model.
	 * @return the MemBuffer beginning at the data type indicated by the ordinal.
	 */
	protected MemBuffer getSpecificMemBuffer(int ordinal, DataType dt) {
		int size = dt.getLength();
		MemBuffer baseMemBuffer = getMemBuffer();
		long offset = size * ordinal;
		Address specificAddress = baseMemBuffer.getAddress().add(offset);
		MemBuffer specificMemBuffer =
			new DumbMemBufferImpl(getProgram().getMemory(), specificAddress);
		return specificMemBuffer;
	}

	/**
	 * Determines if the indicated entryCount value appears valid for the indicated count type.
	 * @param countType name indicating the type of count being checked.
	 * @param actualCount the count of the actual number of entries for an exception handling map.
	 * @param maxValidCount the maximum expected number of entries in an exception handling map.
	 * @throws InvalidDataTypeException if the count is less than zero or greater than the maximum.
	 */
	public void checkEntryCount(String countType, int actualCount, int maxValidCount)
			throws InvalidDataTypeException {
		checkNonNegative(countType, actualCount);
		checkAgainstMaxCount(countType, actualCount, maxValidCount);
	}

	/**
	 * Determines if the indicated actual entry count value is a non-negative count
	 * for the indicated count type.
	 * @param countType name indicating the type of count being checked.
	 * @param actualCount the actual number of entries in a data type map.
	 * @throws InvalidDataTypeException if the count is negative.
	 */
	public void checkNonNegative(String countType, int actualCount)
			throws InvalidDataTypeException {
		if (actualCount < 0) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" has a " + countType + " count of " + actualCount + ", which seems incorrect.");
		}
	}

	/**
	 * Determines if the indicated count value for the number of entries is above the indicated 
	 * maximum valid count value for the indicated count type.
	 * @param countType name indicating the type of count being checked.
	 * @param actualCount the count of the actual number of entries for a data type map.
	 * @param maxValidCount the maximum expected number of entries in a data type map.
	 * @throws InvalidDataTypeException if the count is greater than the maximum.
	 */
	public void checkAgainstMaxCount(String countType, int actualCount, int maxValidCount)
			throws InvalidDataTypeException {
		if (actualCount > maxValidCount) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " has a " + countType + " count of " +
					actualCount + ", which exceeds the expected maximum of " + maxValidCount + ".");
		}
	}

	/**
	 * Determines if data is already defined between the start and end address.
	 * @param listing the program listing where the data type is to be placed.
	 * @param startAddress the start address of the range to check.
	 * @param endAddress the end address of the range to check.
	 * @return true if there is already defined data in the range from the start to end address.
	 */
	boolean containsDefinedData(Listing listing, Address startAddress, Address endAddress) {
		Data data = listing.getDefinedDataContaining(startAddress);
		if (data != null) {
			return true;
		}
		data = listing.getDefinedDataAfter(startAddress);
		if (data != null && data.getMinAddress().compareTo(endAddress) <= 0) {
			return true;
		}
		return false;
	}

	/**
	 * Determines if an instruction is already defined between the start and end address.
	 * @param listing the program listing where the data type is to be placed.
	 * @param startAddress the start address of the range to check.
	 * @param endAddress the end address of the range to check.
	 * @return true if there is already an instruction in the range from the start to end address.
	 */
	boolean containsInstruction(Listing listing, Address startAddress, Address endAddress) {
		Instruction instruction = listing.getInstructionContaining(startAddress);
		if (instruction != null) {
			return true;
		}
		instruction = listing.getInstructionAfter(startAddress);
		if (instruction != null && instruction.getMinAddress().compareTo(endAddress) <= 0) {
			return true;
		}
		return false;
	}

	/**
	 * Gets the current validation options that are set for this model.
	 * @return the validation options
	 */
	protected DataValidationOptions getValidationOptions() {
		return validationOptions;
	}

	/**
	 * Returns the DataOrganization associated with this model's DataTypeManager
	 */
	final protected DataOrganization getDataOrganization() {
		return dataTypeManager.getDataOrganization();
	}

	/**
	 * Determines if the data type, that is returned by any call to a getDataType() method,
	 * is already based on the count as part of the data type (i.e. the data type returned
	 * is an array with count number of elements of an underlying data type.)
	 * @return true if the data type already has count number of elements. false means the
	 * data type isn't based on the count in any way.
	 */
	public boolean isDataTypeAlreadyBasedOnCount() {
		return dataTypeAlreadyBasedOnCount;
	}

	/**
	 * Sets whether or not the data type returned by this model already includes the model's 
	 * count as part of the data type.
	 * @param dataTypeAlreadyBasedOnCount true if the model's data type is already based on the count.
	 * false means the data type returned by the model isn't based on the count in any way.
	 */
	protected void setIsDataTypeAlreadyBasedOnCount(boolean dataTypeAlreadyBasedOnCount) {
		this.dataTypeAlreadyBasedOnCount = dataTypeAlreadyBasedOnCount;
	}

	/**
	 * Gets the default message indicating the data type for this model isn't valid at the 
	 * indicated address.
	 * @return the message
	 */
	protected final String getDefaultInvalidMessage() {
		return getName() + " data type at " + getAddress() + " isn't valid.";
	}

	/**
	 * Throws an InvalidDataTypeException with a default message that indicates the data type 
	 * and address where it is invalid.
	 * 
	 * @throws InvalidDataTypeException which has the message
	 */
	protected void invalid() throws InvalidDataTypeException {
		throw new InvalidDataTypeException(getDefaultInvalidMessage());
	}

	/**
	 * Throws an InvalidDataTypeException with a default message indicating the data type 
	 * and address where it is invalid that is followed by the message from the exception 
	 * passed to this method.
	 * 
	 * @param e the exception which has its message appended to the default message
	 * @throws InvalidDataTypeException which has the message
	 */
	protected void invalid(Exception e) throws InvalidDataTypeException {
		String message = getDefaultInvalidMessage();
		String excMessage = e.getMessage();
		if (excMessage != null && !excMessage.isEmpty()) {
			message += " " + excMessage;
		}
		throw new InvalidDataTypeException(message);
	}

	/**
	 * Throws an InvalidDataTypeException with a default message indicating the data type 
	 * and address where it is invalid that is followed by the suffixMessage passed to this 
	 * method.
	 * 
	 * @param suffixMessage the message to append to the default message
	 * @throws InvalidDataTypeException which has the message
	 */
	protected void invalid(String suffixMessage) throws InvalidDataTypeException {
		String message = getDefaultInvalidMessage();
		if (suffixMessage != null && !suffixMessage.isEmpty()) {
			message += " " + suffixMessage;
		}
		throw new InvalidDataTypeException(message);
	}

}
