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

import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.datatype.microsoft.MSDataTypeUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemangledType;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mdemangler.*;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.complex.MDComplexType;
import mdemangler.datatype.modifier.MDModifierType;
import mdemangler.naming.MDQualifiedName;

/**
 * Model for the TypeDescriptor data type.
 * <br>
 * This is based on data type information from ehdata.h
 */
public class TypeDescriptorModel extends AbstractCreateDataTypeModel {

	public static final String DATA_TYPE_NAME = "TypeDescriptor";
	private static final String STRUCTURE_NAME = DATA_TYPE_NAME;

	private static final int VF_TABLE_OR_HASH_ORDINAL = 0;
	private static final int SPARE_ORDINAL = 1;
	private static final int NAME_ORDINAL = 2; // defined as flexible array component char[0]. It's actually a null terminated string.

	private DataType dataType;
	private boolean hasVFPointer;

	private String originalTypeName;
	private MDComplexType mdComplexType;
	private boolean hasProcessedName = false;
	private Namespace namespace;

	/**
	 * Creates the model for the exception handling TypeDescriptor data type.
	 * @param program the program
	 * @param address the address in the program for the TypeDescriptor data type.
	 */
	public TypeDescriptorModel(Program program, Address address,
			DataValidationOptions validationOptions) {
		super(program, 1, address, validationOptions);
		hasVFPointer = hasVFPointer(program);
	}

	@Override
	public String getName() {
		return DATA_TYPE_NAME;
	}

	@Override
	protected void checkDataType() throws InvalidDataTypeException {
		// Can't create the data type since don't know its size without a null terminated name.
		if (getDataTypeLength() <= 0) {
			throw new InvalidDataTypeException(
				getName() + " @ " + getAddress() + " can't determine a null terminated type name.");
		}
	}

	/**
	 * Whether or not the memory at the indicated address appears to be a valid location for the
	 * indicated number of TypeDescriptor data types.
	 * @throws InvalidDataTypeException if this model's location does not appear to be a valid
	 * group of TypeDescriptors. The exception has a message indicating
	 * why it does not appear to be a valid location for the data type.
	 */
	@Override
	protected void validateModelSpecificInfo() throws InvalidDataTypeException {

		Program program = getProgram();
		Memory memory = program.getMemory();
		AddressSetView loadedAndInitializedSet = memory.getLoadedAndInitializedAddressSet();
		Address startAddress = getAddress();

		// Do we at least have memory for the first 2 components (the pointers).
		int pointerSize = MSDataTypeUtils.is64Bit(program) ? 8 : 4;

		// Test that we can get the expected number of bytes.
		MSDataTypeUtils.getBytes(memory, startAddress, pointerSize * 2);

		// First component should be reference.
		checkVfTablePointerComponent(loadedAndInitializedSet);

		// Check Spare Data. Should be 0 or a valid address in program.
		checkSpareDataComponent(loadedAndInitializedSet);

		checkTypeNameComponent();
	}

	private void checkVfTablePointerComponent(AddressSetView loadedAndInitializedSet)
			throws InvalidDataTypeException {

		try {
			Address vfTableAddress = getVFTableAddress();
			if (vfTableAddress == null || !loadedAndInitializedSet.contains(vfTableAddress)) {
				String message = getName() + " data type at " + getAddress() +
					" doesn't point to a vfTable address in a loaded and initialized memory block.";
				throw new InvalidDataTypeException(message);
			}
		}
		catch (UndefinedValueException e) {
			// If this doesn't have a vf table address throw an exception?
			throw new InvalidDataTypeException(e.getMessage());
		}
	}

	private void checkSpareDataComponent(AddressSetView loadedAndInitializedSet)
			throws InvalidDataTypeException {

		try {
			Address spareDataAddress = getSpareDataAddress();
			if (spareDataAddress != null && spareDataAddress.getOffset() != 0L &&
				!loadedAndInitializedSet.contains(spareDataAddress)) {
				throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
					" doesn't point to a spare data address in a loaded and initialized memory block.");
			}
		}
		catch (AddressOutOfBoundsException e1) {
			throw new InvalidDataTypeException(getName() + " data type at " + getAddress() +
				" doesn't have a valid reference to spare data.");
		}
	}

	private void checkTypeNameComponent() throws InvalidDataTypeException {
		Program program = getProgram();
		Memory memory = program.getMemory();
		Address typeDescriptorAddress = getAddress();
		int pointerSize = getDefaultPointerSize();

		String typeName = doGetTypeName();
		if (typeName == null) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " doesn't have a valid type name.");
		}
		int nameLength = typeName.length();
		if (nameLength == 0) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " doesn't have a valid type name.");
		}

		int lengthWithoutAlignPadding = getNameOffset(program) + nameLength;
		int mod = lengthWithoutAlignPadding % pointerSize;
		int padSize = (mod == 0) ? 0 : (pointerSize - mod);
		int paddedLength = lengthWithoutAlignPadding + padSize;
		try {
			// Test that we can get the expected number of bytes.
			MSDataTypeUtils.getBytes(memory, typeDescriptorAddress, paddedLength);
		}
		catch (InvalidDataTypeException e) {
			String paddingErrorMessage = getName() + " data type at " + getAddress() +
				" doesn't have valid alignment after the vftable name.";
			throw new InvalidDataTypeException(e.getMessage() + "\n" + paddingErrorMessage);
		}

		if (containsWhitespace(typeName)) {
			throw new InvalidDataTypeException(
				getName() + " data type at " + getAddress() + " doesn't have a valid type name.");
		}
	}

	private boolean containsWhitespace(String s) {
		int checkLength = s.length();
		if (s.charAt(checkLength - 1) == 0) {
			checkLength--;
		}

		for (int i = 0; i < checkLength; i++) {
			// Don't allow blanks or control characters which are less than a blank.
			char c = s.charAt(i);
			if (Character.isWhitespace(c)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets the TypeDescriptor structure for the indicated program.
	 * @return the TypeDescriptor structure.
	 */
	public static DataType getDataType(Program program) {

		DataTypeManager dataTypeManager = program.getDataTypeManager();
		CategoryPath categoryPath = new CategoryPath(CATEGORY_PATH);
		StructureDataType struct = isRelative(program)
				? MSDataTypeUtils.getAlignedPack8Structure(dataTypeManager, categoryPath,
					STRUCTURE_NAME)
				: MSDataTypeUtils.getAlignedPack4Structure(dataTypeManager, categoryPath,
					STRUCTURE_NAME);

		PointerDataType pointerDataType =
			new PointerDataType(new VoidDataType(dataTypeManager), dataTypeManager);

		boolean hasVFPointer = hasVFPointer(program);

		// Add the components.
		DataType compDt;

		// First component is vfTable pointer or hash value
		if (hasVFPointer) {
			struct.add(pointerDataType, "pVFTable", null);
		}
		else {
			compDt = new DWordDataType(dataTypeManager);
			struct.add(compDt, "hash", null);
		}

		struct.add(pointerDataType, "spare", null);

		// The final structure component is a flexible-array corresponding to a variable length
		// char array (i.e., null terminated string).  The storage for this array is not
		// included in the length of the structure and must have a properly sized char array
		// created immediately following the structure in memory.

		struct.setFlexibleArrayComponent(CharDataType.dataType, "name", null);

		return MSDataTypeUtils.getMatchingDataType(program, struct);
	}

	/**
	 * Determine if this model's data type has a vf table pointer.
	 * @param program the program which will contain this model's data type.
	 * @return true if the data type has a vf table pointer. Otherwise, it has a hash value.
	 */
	private static boolean hasVFPointer(Program program) {

		Address typeInfoVftableAddress = null;
		try {
			typeInfoVftableAddress = RttiUtil.findTypeInfoVftableAddress(program, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e);
		}
		if (typeInfoVftableAddress != null) {
			return true;
		}
		return false;
	}

	/**
	 * Gets the TypeDescriptor structure for this model's program.
	 * @return the TypeDescriptor structure.
	 */
	@Override
	public DataType getDataType() {
		if (dataType == null) {
			dataType = getDataType(getProgram());
		}
		return dataType;
	}

	@Override
	protected int getDataTypeLength() {
		Structure struct = (Structure) getDataType();
		DataTypeComponent nameComponent = struct.getFlexibleArrayComponent();
		int preNameLength = nameComponent.getOffset();
		int totalLength = preNameLength;
		// Add the length of the name string too if we can get it.
		Address nameAddress = getAddress().add(preNameLength);
		TerminatedStringDataType terminatedStringDt =
			new TerminatedStringDataType(getProgram().getDataTypeManager());
		DumbMemBufferImpl nameMemBuffer =
			new DumbMemBufferImpl(getMemBuffer().getMemory(), nameAddress);
		int nameLength =
			terminatedStringDt.getLength(nameMemBuffer, StringDataInstance.MAX_STRING_LENGTH);
		if (nameLength <= 0) {
			return 0; // Can't get name, so return 0 for invalid.
		}
		totalLength += nameLength;
		// Add on bytes for alignment at the end.
		int alignment = getAlignment();
		int mod = totalLength % alignment;
		if (mod != 0) {
			int numAlignBytes = alignment - mod;
			totalLength += numAlignBytes;
		}
		return totalLength;
	}

	@Override
	protected int getAlignment() {
		DataType dt = getDataType();
		if (dt != null) {
			return dt.getAlignment();
		}
		return isRelative() ? 8 : 4;
	}

	/**
	 * Gets the offset of the vf table address in the Type Descriptor structure.
	 * @return the offset of the vf table address
	 */
	public int getVFTableAddressOffset() {
		return VF_TABLE_OR_HASH_ORDINAL;
	}

	/**
	 * Gets the offset of the spare data pointer in the Type Descriptor structure.
	 * @return the offset of the spare data pointer
	 */
	public int getSpareDataOffset() {
		return MSDataTypeUtils.is64Bit(getProgram()) ? 8 : 4;
	}

	/**
	 * Gets the offset of the name in the Type Descriptor structure.
	 * @return the offset of the name
	 */
	public int getNameOffset() {
		return getNameOffset(getProgram());
	}

	private static int getNameOffset(Program program) {
		return MSDataTypeUtils.is64Bit(program) ? 16 : 8;
	}

	/**
	 * Gets the address of the vf table or null if one isn't indicated.
	 * @return the address of the vf table or null.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 * @throws UndefinedValueException if the type descriptor doesn't have a vf table pointer
	 * component.
	 */
	public Address getVFTableAddress() throws InvalidDataTypeException, UndefinedValueException {
		checkValidity();
		if (!hasVFPointer) {
			throw new UndefinedValueException(
				"No vf table pointer is defined for this TypeDescriptor model.");
		}
		
		Address vfTableAddress;
		// component 0 is either vf table pointer or hash value.
		vfTableAddress = EHDataTypeUtilities.getAddress(getDataType(), VF_TABLE_OR_HASH_ORDINAL, getMemBuffer());

		return vfTableAddress.getOffset() != 0 ? vfTableAddress : null;
	}

	/**
	 * Gets the hash value if this data type has one.
	 * @return the hash value.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 * @throws UndefinedValueException if the type descriptor doesn't have a hash value.
	 */
	public Scalar getHashValue() throws InvalidDataTypeException, UndefinedValueException {
		checkValidity();
		if (hasVFPointer) {
			throw new UndefinedValueException(
				"No hash value is defined for this TypeDescriptor model.");
		}
		// component 0 is either vf table pointer or hash value.
		return EHDataTypeUtilities.getScalarValue(getDataType(), VF_TABLE_OR_HASH_ORDINAL,
			getMemBuffer());
	}

	/**
	 * Gets the address of the spare data or null if none is indicated.
	 * @return the address of the spare data or null.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 */
	public Address getSpareDataAddress() throws InvalidDataTypeException {
		checkValidity();
		// component 1 is the spare data.
		Address spareAddress =
			EHDataTypeUtilities.getAddress(getDataType(), SPARE_ORDINAL, getMemBuffer());
		return spareAddress.getOffset() != 0 ? spareAddress : null;
	}

	/**
	 * Gets the actual name string for this type descriptor.
	 * @return the type name or null.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 */
	public String getTypeName() throws InvalidDataTypeException {
		if (originalTypeName != null) {
			return originalTypeName;
		}
		try {
			checkValidity();
		}
		catch (Exception e) {
			hasProcessedName = true; // Invalid model.
			throw e;
		}
		String typeName = doGetTypeName(); // Can return null.
		if (typeName == null) {
			throw new InvalidDataTypeException("Can't determine type name for " + getName() +
				" data type at " + getAddress() + ".");
		}
		return typeName;
	}

	/**
	 * Gets the actual name string for this type descriptor.
	 * @return the type name or null.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 */
	private String doGetTypeName() throws InvalidDataTypeException {
		// last component is the type descriptor name.
		Address nameAddress = getComponentAddressOfTypeName(); // Could be null.
		if (nameAddress == null) {
			return null;
		}
		Program program = getProgram();
		TerminatedStringDataType terminatedStringDt =
			new TerminatedStringDataType(program.getDataTypeManager());
		DumbMemBufferImpl nameMemBuffer =
			new DumbMemBufferImpl(getMemBuffer().getMemory(), nameAddress);
		Object value = terminatedStringDt.getValue(nameMemBuffer, SettingsImpl.NO_SETTINGS, 1);
		if (value instanceof String) {
			originalTypeName = (String) value;
			if (originalTypeName != null) {
				mdComplexType = getMDComplexType(program, originalTypeName); // Can be null.
			}
		}
		hasProcessedName = true;
		return originalTypeName;
	}

	private boolean hasComplexType() {
		if (!hasProcessedName) {
			try {
				getTypeName(); // Initialize originalTypeName & mdComplexType if possible.
			}
			catch (InvalidDataTypeException e) {
				return false;
			}
		}
		return (mdComplexType != null);
	}

	/**
	 * Gets the demangled name string for this type descriptor.
	 * This is the refType and full name including namespaces.
	 * @return the full demangled type name or null.
	 */
	public String getDemangledTypeDescriptor() {
		return hasComplexType() ? mdComplexType.toString() : null;
	}

	/**
	 * Gets the reference type of the type descriptor. (i.e. class, struct, union, enum)
	 * @return the type of thing referred to by this descriptor, or null if it couldn't be
	 * determined.
	 */
	public String getRefType() {
		return hasComplexType() ? mdComplexType.getTypeName() : null;
	}

	/**
	 * Gets just the name of the type descriptor.
	 * @return the name of the thing referred to by this descriptor, or null if it couldn't
	 * be determined.
	 */
	public String getDescriptorName() {
		if (!hasComplexType()) {
			return null;
		}
		MDQualifiedName qualifiedName = mdComplexType.getNamespace();
		return qualifiedName.getName();
	}

	/**
	 * Gets the parent namespace of the type descriptor.
	 * @return the parent namespace as a DemangledType or null.
	 */
	public DemangledType getParentNamespace() {
		if (!hasComplexType()) {
			return null;
		}
		MDQualifiedName qualifiedName = mdComplexType.getNamespace();
		MDMangGhidra demangler = new MDMangGhidra();
		return demangler.processNamespace(qualifiedName);
	}

	/**
	 * Gets the full pathname (includes namespaces) of the type descriptor.
	 * This may include modifiers. It doesn't contain the refType.
	 * @return the full pathname or null.
	 */
	public String getDescriptorTypeNamespace() {
		return hasComplexType() ? mdComplexType.getTypeNamespace() : null;
	}

	/**
	 * Gets the address of where to find the type name, if there is one.
	 * Otherwise, this returns null.
	 * @return the address of the component with the type descriptor address or null.
	 * @throws InvalidDataTypeException if valid TypeDescriptor data can't be created at the
	 * model's address.
	 */
	public Address getComponentAddressOfTypeName() throws InvalidDataTypeException {
		checkValidity();
		DataType dt = getDataType();
		if (dt == null) {
			return null;
		}
		Structure struct = (Structure) dt;
		DataTypeComponent nameComponent = struct.getComponent(NAME_ORDINAL);
		// alternative: DataTypeComponent nameComponent = struct.getFlexibleArrayComponent(); // name[0] component
		int offset = nameComponent.getOffset();
		Address addressOfName;
		try {
			addressOfName = getAddress().add(offset);
			return addressOfName;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	/**
	 * Determines the address where the TypeDescriptor structure would need to begin in order
	 * for the type name to begin at the address specified by <code>typeNameAddress</code>.
	 * @param program the program that would contain the TypeDescriptor.
	 * @param typeNameAddress the address where the type descriptor name begins.
	 * @return the base address of the TypeDescriptor or null.
	 */
	public static Address getBaseAddress(Program program, Address typeNameAddress) {
		int nameOffset = getNameOffset(program);
		try {
			return typeNameAddress.subtractNoWrap(nameOffset);
		}
		catch (AddressOverflowException e) {
			return null; //Can't get a valid base address.
		}
	}

	/**
	 * Whether or not the memory at the the model's address appears to be a valid location for a
	 * Type Descriptor data type and that its virtual function table address matches the specified
	 * address.
	 * @param expectedVFTableAddress the virtual function table address that the model is expected
	 * to match.
	 * @throws InvalidDataTypeException if this model's location doesn't appear to be valid for
	 * the indicated data type. The exception has a message indicating why it does not appear to
	 * be a valid location for the data type.
	 * @throws UndefinedValueException if the type descriptor doesn't have a vf table pointer
	 * component.
	 */
	public void validate(Address expectedVFTableAddress)
			throws InvalidDataTypeException, UndefinedValueException {

		validate();

		Address vfTableAddress = getVFTableAddress();
		if (expectedVFTableAddress != null && !expectedVFTableAddress.equals(vfTableAddress)) {
			String message = getName() + " data type at " + getAddress() +
				" wouldn't have expected vfTable address of " + expectedVFTableAddress + ".";
			throw new InvalidDataTypeException(message);
		}
	}

	/**
	 * Gets the namespace for this descriptor. It will create the namespace if it doesn't already exist.
	 * @return the descriptor's namespace, or null if it couldn't be determined.
	 */
	public Namespace getDescriptorAsNamespace() {
		if (namespace == null || isNamespaceDeleted(namespace)) {
			String descriptorName = getDescriptorName(); // Can be null.
			if (descriptorName == null) {
				return null;
			}

			String demangledSource = mdComplexType.toString();
			DemangledType typeNamespace =
				new DemangledType(originalTypeName, demangledSource, descriptorName);
			DemangledType parentNamespace = getParentNamespace(); // Can be null;
			if (parentNamespace != null) {
				typeNamespace.setNamespace(parentNamespace);
			}
			Program program = getProgram();
			namespace = DemangledObject.createNamespace(program, typeNamespace,
				program.getGlobalNamespace(), false);
		}
		return namespace;
	}

	private boolean isNamespaceDeleted(Namespace other) {
		Symbol nsSymbol = other.getSymbol();
		if (nsSymbol == null) {
			return false; // global namespace.
		}
		return nsSymbol.isDeleted();
	}

	/**
	 * Gets a demangler complex type for the indicated mangled string.
	 * @param program the program containing the mangled string
	 * @param mangledString the mangled string to be decoded
	 * @return the associated complex type or null if the string couldn't be demangled.
	 */
	private static MDComplexType getMDComplexType(Program program, String mangledString) {
		MDMangGhidra demangler = new MDMangGhidra();
		try {
			MDParsableItem parsableItem = demangler.demangle(mangledString, true);
			if (!(parsableItem instanceof MDDataType)) {
				// Not an MDDataType as expected.
				return null;
			}
			MDDataType mangledDt = (MDDataType) parsableItem;
			if (mangledDt instanceof MDModifierType) {
				MDModifierType modifierType = (MDModifierType) mangledDt;
				MDType refType = modifierType.getReferencedType();
				if (refType instanceof MDComplexType) {
					return (MDComplexType) refType;
				}
			}
			return null; // Not an MDComplexType
		}
		catch (MDException e) {
			// Couldn't demangle.
			return null;
		}
	}

}
