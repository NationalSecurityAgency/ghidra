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
package ghidra.app.util.datatype.microsoft;

import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.getAbsoluteAddress;
import static ghidra.app.util.datatype.microsoft.MSDataTypeUtils.is64Bit;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.Msg;

/**
 * The RTTI0 data type represents a TypeDescriptor structure.
 * <p>
 * Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
 * <p>
 * <pre>
 * struct TypeDescriptor {
 *     Pointer vfTablePointer;
 *     Pointer dataPointer;
 *     NullTerminatedString name; // mangled version of class name
 * }
 * </pre>
 * <p>
 * RTTI_Type_Descriptor is the label for the RTTI0 data structure.
 */
public class RTTI0DataType extends RTTIDataType {

	private final static long serialVersionUID = 1;
	private final static int VF_TABLE_POINTER_OFFSET = 0;

	/**
	 * Creates a dynamic Type Descriptor data type.
	 */
	public RTTI0DataType() {
		this(null);
	}

	/**
	 * Creates a dynamic Type Descriptor data type.
	 * @param dtm the data type manager for this data type.
	 */
	public RTTI0DataType(DataTypeManager dtm) {
		super("RTTI_0", dtm);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new RTTI0DataType(dtm);
	}

	@Override
	public String getDescription() {
		return "RTTI 0 (RTTI Type Descriptor) Structure used to provide type information for a C++ class.";
	}

	@Override
	public String getMnemonic(Settings settings) {
		return "RTTI_0";
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
//		return StructureParser.getAddress(buf.getMemory(), buf.getAddress()).toString(); // Get the vftableAddress for now
//		return getVFTableName(buf); // Get the vftableName for now
		//changed to be consistent with the others - it didn't make sense to only show the first item in the structure in the rep field
		return "";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
//		return StructureParser.getAddress(buf.getMemory(), buf.getAddress()); // Get the vftableAddress for now
//		return getVFTableName(buf); // Get the vftableName for now
		//changed to return null to be consistent with the others - it makes no sense to return the first field as the value for the whole struct
		return null;
	}

	@Override
	protected DataTypeComponent[] getAllComponents(MemBuffer buf) {
		Program program = buf.getMemory().getProgram();
		Pointer pointer = new PointerDataType(program.getDataTypeManager());
		DataTypeComponent[] comps = new DataTypeComponent[3];
		comps[0] = new ReadOnlyDataTypeComponent(pointer, this, pointer.getLength(), 0,
			VF_TABLE_POINTER_OFFSET, "pVFTable", "vfTablePointer");
		int dataPointerOffset = getSpareDataOffset(program);
		comps[1] = new ReadOnlyDataTypeComponent(pointer, this, pointer.getLength(), 1,
			dataPointerOffset, "spare", "pointer to spare data");
		Address start = buf.getAddress();
		int nameOffset = getNameOffset(program);
		Address nameAddress = start.add(nameOffset);
		MemoryBufferImpl nameBuf = new MemoryBufferImpl(buf.getMemory(), nameAddress, 1024);
		DataTypeInstance dti =
			DataTypeInstance.getDataTypeInstance(new TerminatedStringDataType(), nameBuf);

		if (dti != null) {
			comps[2] = new ReadOnlyDataTypeComponent(dti.getDataType(), this, dti.getLength(), 2,
				nameOffset, "name", null);
		}
		else {
			comps[2] = new ReadOnlyDataTypeComponent(DataType.DEFAULT, this, 1, 2, nameOffset,
				"name", null);
		}
		int length = nameOffset + dti.getLength();
		int pointerSize = is64Bit(program) ? 8 : 4;
		int mod = length % pointerSize;
		if (mod == 0) {
			return comps;
		}

		int offset = length;
		int bytesNeeded = (mod != 0) ? (pointerSize - mod) : 0;
		DataType dt = new ArrayDataType(new ByteDataType(), bytesNeeded, 1);
		DataTypeComponent[] alignedComps = new DataTypeComponent[4];
		System.arraycopy(comps, 0, alignedComps, 0, 3);
		alignedComps[3] =
			new ReadOnlyDataTypeComponent(dt, this, bytesNeeded, 3, offset, "alignmentBytes", null);
		return alignedComps;
	}

	private int getSpareDataOffset(Program program) {
		return is64Bit(program) ? 8 : 4;
	}

	private int getNameOffset(Program program) {
		return is64Bit(program) ? 16 : 8;
	}

	/**
	 * Gets the address of the vf table or null if one isn't indicated.
	 * @param memory the program memory containing the address
	 * @param rtti0Address the address for the RTTI 0
	 * @return the address of the vf table or null.
	 */
	public Address getVFTableAddress(Memory memory, Address rtti0Address) {
		return getAbsoluteAddress(memory.getProgram(), rtti0Address);
	}

	/**
	 * Gets the address of the spare data, a 0 address if there is no spare data,
	 * or null.
	 * @param memory the program memory containing the address
	 * @param rtti0Address the address for the RTTI 0
	 * @return the address of the spare data, a 0 value, or null.
	 */
	public Address getSpareDataAddress(Memory memory, Address rtti0Address) {
		int spareDataOffset = getSpareDataOffset(memory.getProgram());
		return getAbsoluteAddress(memory.getProgram(), rtti0Address.add(spareDataOffset));
	}

	/**
	 * Gets the type name for this descriptor.
	 * @param buf the memory buffer where data has been created with this data type.
	 * @return the name
	 */
	public String getVFTableName(MemBuffer buf) {
		DataTypeInstance dti = null;
		WrappedMemBuffer nameBuf = null;
		try {
			nameBuf = new WrappedMemBuffer(buf, getNameOffset(buf.getMemory().getProgram()));
			dti = DataTypeInstance.getDataTypeInstance(new TerminatedStringDataType(), nameBuf);
		}
		catch (AddressOutOfBoundsException e) {
			// ignore
		}

		if (dti == null || dti.getLength() > 1024) {
			Msg.warn(this, "Couldn't get vf table name @ " + buf.getAddress() + ".");
			return null;
		}

		String s = dti.getDataType().getValue(nameBuf, SettingsImpl.NO_SETTINGS,
			dti.getLength()).toString();
		return s;
	}

	/**
	 * Gets the total length of the data created when this data type is placed at the indicated
	 * address in memory.
	 * @param memory the program memory for this data.
	 * @param address the start address of the data.
	 * @param bytes the bytes for this data.
	 * @return the length of the data. zero is returned if valid data can't be created at the
	 * indicated address using this data type.
	 */
	public int getLength(Memory memory, Address address, byte[] bytes) {
		Program program = memory.getProgram();
		// Align this structure based on pointer size so the pointers have proper alignment.
		int pointerSize = is64Bit(program) ? 8 : 4;
		if (address.getOffset() % pointerSize != 0) {
			return 0;
		}
		// Check that we have enough bytes for the expected pointers and at least 1 byte for the
		// name string.
		if (bytes.length < (pointerSize * 2) + 1) {
			return 0;
		}
		// First component should be direct reference. (This is actually a pointer to the class functions.)
		Address vfTableAddress = getAbsoluteAddress(program, address);
		if (vfTableAddress == null || !memory.contains(vfTableAddress)) {
			return 0;
		}
		int nameOffset = getNameOffset(program);
		// Next component should be zeros. (This is actually a pointer to the class data if any.)
		for (int i = getSpareDataOffset(program); i < nameOffset; i++) {
			if (bytes[i] != 0) {
				return 0;
			}
		}
		String vfTableName = getVFTableName(new MemoryBufferImpl(memory, address));
		if (vfTableName == null) {
			return 0;
		}
		int nameLength = vfTableName.length();
		if (nameLength == 0) {
			return 0;
		}
		int lengthWithoutAlignPadding = nameOffset + nameLength;
		int mod = lengthWithoutAlignPadding % pointerSize;
		int padSize = (mod == 0) ? 0 : (pointerSize - mod);
		int paddedLength = lengthWithoutAlignPadding + padSize;
		if (paddedLength > bytes.length) {
			return 0;
		}
		if (containsWhitespace(vfTableName)) {
			return 0;
		}
		return paddedLength;
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

	@Override
	public boolean isValid(Program program, final Address startAddress,
			DataValidationOptions validationOptions) {

		Memory memory = program.getMemory();
		AddressSetView loadedAndInitializedSet = memory.getLoadedAndInitializedAddressSet();
		Listing listing = program.getListing();

		if (!memory.contains(startAddress)) {
			return false;
		}

		int pointerSize = is64Bit(program) ? 8 : 4;
		Address endAddress = startAddress.add(pointerSize * 2); // 2 pointers plus at least one additional byte.
		try {
			MSDataTypeUtils.getBytes(memory, startAddress, pointerSize * 2);
		}
		catch (InvalidDataTypeException e) {
			return false; // Couldn't get enough bytes from memory.
		}

		// Address should start on a byte boundary based on pointer size.
		if (startAddress.getOffset() % pointerSize != 0) {
			return false;
		}
		// First component should be reference.
		Address vfTableAddress = getAbsoluteAddress(program, startAddress);
		if (vfTableAddress == null || !memory.contains(vfTableAddress)) {
			return false;
		}

		// Check Spare Data. Should be 0 or a valid address in program.
		try {
			Address spareDataAddress = getSpareDataAddress(memory, startAddress);
			if (spareDataAddress != null && spareDataAddress.getOffset() != 0L &&
				!loadedAndInitializedSet.contains(spareDataAddress)) {
				return false;
			}
		}
		catch (AddressOutOfBoundsException e1) {
			return false;
		}

		String vfTableName = getVFTableName(new MemoryBufferImpl(memory, startAddress));
		if (vfTableName == null) {
			return false;
		}
		int nameLength = vfTableName.length();
		if (nameLength == 0) {
			return false;
		}
		int lengthWithoutAlignPadding = getNameOffset(program) + nameLength;
		int mod = lengthWithoutAlignPadding % pointerSize;
		int padSize = (mod == 0) ? 0 : (pointerSize - mod);
		int paddedLength = lengthWithoutAlignPadding + padSize;
		try {
			MSDataTypeUtils.getBytes(memory, startAddress, paddedLength);
		}
		catch (InvalidDataTypeException e) {
			return false; // Couldn't get enough bytes from memory for an entire padded Rtti0.
		}
		if (containsWhitespace(vfTableName)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreInstructions() &&
			containsInstruction(listing, startAddress, endAddress)) {
			return false;
		}

		if (!validationOptions.shouldIgnoreDefinedData() &&
			containsDefinedData(listing, startAddress, endAddress)) {
			return false;
		}

		return true;
	}

	/**
	 * Gets the total length of the data created when this data type is placed at the indicated
	 * address in memory.
	 * @param memory the program memory for this data.
	 * @param startAddress the start address of the data.
	 * @return the length of the data. zero is returned if valid data can't be created at the
	 * indicated address using this data type.
	 */
	public int getLength(Memory memory, Address startAddress) {
		Program program = memory.getProgram();
		int preNameLength = getNameOffset(program);
		int totalLength = preNameLength;
		// Add the length of the name string too if we can get it.
		Address nameAddress = startAddress.add(preNameLength);
		TerminatedStringDataType terminatedStringDt =
			new TerminatedStringDataType(program.getDataTypeManager());
		DumbMemBufferImpl nameMemBuffer = new DumbMemBufferImpl(memory, nameAddress);
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
	public String getDefaultLabelPrefix() {
		return "RTTI_0";
	}
}
