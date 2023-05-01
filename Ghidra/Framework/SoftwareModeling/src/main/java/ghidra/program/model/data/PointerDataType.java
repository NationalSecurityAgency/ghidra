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
package ghidra.program.model.data;

import java.util.*;
import java.util.function.Consumer;

import ghidra.docking.settings.Settings;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.DataConverter;
import ghidra.util.StringUtilities;

/**
 * Basic implementation for a pointer dataType
 */
public class PointerDataType extends BuiltIn implements Pointer {

	public final static PointerDataType dataType = new PointerDataType();

	public final static int MAX_POINTER_SIZE_BYTES = 8;

	public static final String POINTER_NAME = "pointer";
	public static final String POINTER_LABEL_PREFIX = "PTR";
	public static final String POINTER_LOOP_LABEL_PREFIX = "PTR_LOOP";
	public static final String NOT_A_POINTER = "NaP";

	// NOTE: order dictates auto-name attribute ordering (order should not be changed)
	private static TypeDefSettingsDefinition[] POINTER_TYPEDEF_SETTINGS_DEFS =
		{ PointerTypeSettingsDefinition.DEF, AddressSpaceSettingsDefinition.DEF,
			OffsetMaskSettingsDefinition.DEF, OffsetShiftSettingsDefinition.DEF,
			ComponentOffsetSettingsDefinition.DEF };

	protected DataType referencedDataType;
	protected int length;

	private boolean deleted = false;
	private String displayName;

	/**
	 * <code>isEquivalentActive</code> is used to break cyclical recursion when
	 * performing an {@link #isEquivalent(DataType)} checks on pointers which must
	 * also check the base datatype equivelency.
	 */
	private ThreadLocal<Boolean> isEquivalentActive = ThreadLocal.withInitial(() -> Boolean.FALSE);

	/**
	 * Creates a dynamically-sized default pointer data type. A dynamic pointer size
	 * of 4-bytes will be in used, but will adapt to a data type manager's data
	 * organization when resolved.
	 */
	public PointerDataType() {
		this(null, -1, null);
	}

	/**
	 * Creates a dynamically-sized default pointer data type. The pointer size is
	 * established dynamically based upon the data organization associated with the
	 * specified dtm but can adapt to another data type manager's data organization
	 * when resolved.
	 * 
	 * @param dtm data-type manager whose data organization should be used
	 */
	public PointerDataType(DataTypeManager dtm) {
		this(null, -1, dtm);
	}

	/**
	 * Construct a dynamically-sized pointer to a referencedDataType A dynamic
	 * pointer size of 4-bytes will be in used, but will adapt to a data type
	 * manager's data organization when resolved.
	 * 
	 * @param referencedDataType data type this pointer points to
	 */
	public PointerDataType(DataType referencedDataType) {
		this(referencedDataType, -1, null);
	}

	/**
	 * Construct a pointer of a specified length to a referencedDataType. Note: It
	 * is preferred to use default sized pointers when possible (i.e., length=-1,
	 * see {@link #PointerDataType(DataType)}) instead of explicitly specifying the
	 * pointer length value.
	 * 
	 * @param referencedDataType data type this pointer points to
	 * @param length             pointer length (values &lt;= 0 will result in
	 *                           dynamically-sized pointer)
	 */
	public PointerDataType(DataType referencedDataType, int length) {
		this(referencedDataType, length, null);
	}

	/**
	 * Construct a dynamically-sized pointer to the given data type. The pointer
	 * size is established dynamically based upon the data organization associated
	 * with the specified dtm but can adapt to another data type manager's data
	 * organization when resolved.
	 * 
	 * @param referencedDataType data type this pointer points to
	 * @param dtm                data-type manager whose data organization should be
	 *                           used
	 */
	public PointerDataType(DataType referencedDataType, DataTypeManager dtm) {
		this(referencedDataType, -1, dtm);
	}

	/**
	 * Construct a pointer of a specified length to a referencedDataType. Note: It
	 * is preferred to use default sized pointers when possible (i.e., length=-1,
	 * see {@link #PointerDataType(DataType, DataTypeManager)}) instead of
	 * explicitly specifying the pointer length value.
	 * 
	 * @param referencedDataType data type this pointer points to
	 * @param length             pointer length (-1 will result in dynamically-sized
	 *                           pointer)
	 * @param dtm                associated data type manager whose data
	 *                           organization will be used
	 */
	public PointerDataType(DataType referencedDataType, int length, DataTypeManager dtm) {
		super(referencedDataType != null ? referencedDataType.getCategoryPath() : null,
			constructUniqueName(referencedDataType, length), dtm);
		if (referencedDataType instanceof BitFieldDataType) {
			throw new IllegalArgumentException(
				"Pointer reference data-type may not be a bitfield: " +
					referencedDataType.getName());
		}
		this.length = length <= 0 ? -1 : length;
		this.referencedDataType = referencedDataType;
		if (referencedDataType != null) {
			referencedDataType.addParent(this);
		}
	}

	@Override
	public final Pointer clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		// don't clone referenced data-type to avoid potential circular reference
		return new PointerDataType(referencedDataType, length, dtm);
	}

	@Override
	public DataType getDataType() {
		return referencedDataType;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return length <= 0;
	}

	@Override
	public int getLength() {
		return length <= 0 ? getDataOrganization().getPointerSize() : length;
	}

	@Override
	public int getAlignedLength() {
		return getLength();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return POINTER_LABEL_PREFIX;
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		return getLabelString(buf, settings, getLength(), options);
	}

	public static String getLabelString(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {

		Program program = buf.getMemory().getProgram();
		if (program == null) {
			return POINTER_LABEL_PREFIX;
		}

		Address fromAddr = buf.getAddress();

		ReferenceManager refMgr = program.getReferenceManager();
		Reference ref = refMgr.getPrimaryReferenceFrom(fromAddr, 0);
		if (ref == null) {
			return POINTER_LABEL_PREFIX;
		}

		PointerReferenceClassification pointerClassification =
			getPointerClassification(program, ref);
		if (pointerClassification == PointerReferenceClassification.DEEP) {
			// pointer exceed depth limit of 2
			return POINTER_LABEL_PREFIX + "_" + POINTER_LABEL_PREFIX;
		}
		if (pointerClassification == PointerReferenceClassification.LOOP) {
			return POINTER_LOOP_LABEL_PREFIX;// pointer is self referencing
		}

		Symbol symbol = program.getSymbolTable().getSymbol(ref);
		if (symbol == null) {
			// unexpected
			return POINTER_LABEL_PREFIX;
		}

		String symName = symbol.getName();
		symName = SymbolUtilities.getCleanSymbolName(symName, ref.getToAddress());
		symName = symName.replace(Namespace.DELIMITER, "_");
		return POINTER_LABEL_PREFIX + "_" + symName;
	}

	private enum PointerReferenceClassification {
		// NORMAL - use recursive name generation (e.g., PTR_PTR_BYTE)
		NORMAL,
		// LOOP - references loop back - use label prefix PTR_LOOP
		LOOP,
		// DEEP - references are too deep - use simple default label prefix
		DEEP
	}

	private static PointerReferenceClassification getPointerClassification(Program program,
			Reference ref) {

		Address fromAddr = ref.getFromAddress();

		Set<Address> refAddrs = new HashSet<>();
		refAddrs.add(fromAddr);
		int depth = 0;
		while (ref != null && ref.isMemoryReference()) {
			Address toAddr = ref.getToAddress();
			if (!refAddrs.add(toAddr)) {
				return PointerReferenceClassification.LOOP;
			}
			if (++depth > 2) {
				return PointerReferenceClassification.DEEP;
			}
			Data data = getDataAt(program, toAddr);
			if (data == null) {
				break;
			}
			ref = data.getPrimaryReference(0);
		}
		return PointerReferenceClassification.NORMAL;
	}

	private static Data getDataAt(Program program, Address addr) {
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(addr);
		if (data != null) {
			int offset = (int) addr.subtract(data.getAddress());
			if (offset != 0) {
				data = data.getPrimitiveAt(offset);
			}
		}
		return data;
	}

	@Override
	public String getDisplayName() {
		// NOTE: Pointer display name only specifies length if null base type
		if (displayName == null) {
			DataType dt = getDataType();
			if (dt == null) {
				displayName = POINTER_NAME;
				if (length > 0) {
					displayName += Integer.toString(8 * length);
				}
			}
			else {
				displayName = dt.getDisplayName() + " *";
			}
		}
		return displayName;
	}

	/**
	 * Return a unique name for this pointer
	 */
	private static String constructUniqueName(DataType referencedDataType, int ptrLength) {
		if (referencedDataType == null) {
			String s = POINTER_NAME;
			if (ptrLength > 0) {
				s += Integer.toString(8 * ptrLength);
			}
			return s;
		}
		String s = referencedDataType.getName() + " *";
		if (ptrLength > 0) {
			s += Integer.toString(8 * ptrLength);
		}
		return s;
	}

	@Override
	public String getDescription() {
		StringBuilder sbuf = new StringBuilder();
		if (length > 0) {
			sbuf.append(Integer.toString(8 * length));
			sbuf.append("-bit ");
		}
		sbuf.append(POINTER_NAME);
		DataType dt = getDataType();
		if (dt != null) {
			sbuf.append(" to ");
			if (dt instanceof Pointer) {
				sbuf.append(getDataType().getDescription());
			}
			else {
				sbuf.append(getDataType().getDisplayName());
			}
		}
		return sbuf.toString();
	}

	@Override
	public String getMnemonic(Settings settings) {
		if (referencedDataType == null || referencedDataType == DataType.DEFAULT) {
			return "addr";
		}
		return referencedDataType.getMnemonic(settings) + " *";
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int len) {
		return getAddressValue(buf, getLength(), settings);
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Address.class;
	}

	@Override
	public TypeDefSettingsDefinition[] getTypeDefSettingsDefinitions() {
		return POINTER_TYPEDEF_SETTINGS_DEFS;
	}

	/**
	 * Generate an address value based upon bytes stored at the specified buf
	 * location.  Interpretation of settings may depend on access to a {@link Memory} 
	 * object associated with the specified {@link MemBuffer} buf.
	 * <BR>
	 * The following pointer-typedef settings are supported:
	 * <ul>
	 * <li>{@link AddressSpaceSettingsDefinition}</li>
	 * <li>{@link OffsetMaskSettingsDefinition}</li>
	 * <li>{@link OffsetShiftSettingsDefinition}</li>
	 * <li>{@link PointerTypeSettingsDefinition}</li>
	 * </ul>
	 * 
	 * @param buf memory buffer positioned to stored pointer
	 * @param size pointer size in bytes
	 * @param settings settings which may influence address generation
	 * @return address value or null if unusable buf or data 
	 */
	public static Address getAddressValue(MemBuffer buf, int size, Settings settings) {
		return getAddressValue(buf, size, settings, msg -> {
			/* ignore */});
	}

	/**
	 * Generate an address value based upon bytes stored at the specified buf
	 * location.  Interpretation of settings may depend on access to a {@link Memory} 
	 * object associated with the specified {@link MemBuffer} buf.
	 * <BR>
	 * The following pointer-typedef settings are supported:
	 * <ul>
	 * <li>{@link AddressSpaceSettingsDefinition}</li>
	 * <li>{@link OffsetMaskSettingsDefinition}</li>
	 * <li>{@link OffsetShiftSettingsDefinition}</li>
	 * <li>{@link PointerTypeSettingsDefinition}</li>
	 * </ul>
	 * 
	 * @param buf memory buffer positioned to stored pointer
	 * @param size pointer size in bytes
	 * @param settings settings which may influence address generation
	 * @param errorHandler if null returned an error may be conveyed to this errorHandler
	 * @return address value or null if unusable buf or data 
	 */
	public static Address getAddressValue(MemBuffer buf, int size, Settings settings,
			Consumer<String> errorHandler) {

		String spaceName = AddressSpaceSettingsDefinition.DEF.getValue(settings);
		AddressSpace targetSpace = null;

		Memory mem = buf.getMemory();

		boolean signedOffset = false;
		PointerType pointerType = PointerTypeSettingsDefinition.DEF.getType(settings);
		if (pointerType == PointerType.RELATIVE) {
			signedOffset = true;
		}

		Long offset = getStoredOffset(buf, size, signedOffset, errorHandler);
		if (offset == null) {
			return null;
		}

		long addrOffset = offset;

		long mask = OffsetMaskSettingsDefinition.DEF.getValue(settings);
		if (mask == 0) {
			errorHandler.accept("Invalid pointer mask: 0");
			return null;
		}
		if (mask != OffsetMaskSettingsDefinition.DEFAULT) {
			addrOffset &= mask;
		}

		int shift = (int) OffsetShiftSettingsDefinition.DEF.getValue(settings);
		if (shift < 0) {
			if (signedOffset) {
				addrOffset >>= -shift; // signed right-shift
			}
			else {
				addrOffset >>>= -shift; // unsigned right-shift
			}
		}
		else if (shift > 0) {
			addrOffset <<= shift; // left-shift
		}

		try {
			if (pointerType != PointerType.DEFAULT && spaceName != null) {
				errorHandler.accept("Address Space and Pointer Type settings conflict");
				return null;
			}
			// Address space setting ignored if Pointer Type has been specified
			if (pointerType == PointerType.IMAGE_BASE_RELATIVE) {
				if (addrOffset == 0) {
					// Done for consistency with old ImageBaseOffsetDataType.
					// A 0 relative offset is considerd invalid (NaP)
					return null; // NaP without error
				}
				if (mem == null) {
					errorHandler.accept("Memory not specified");
				}
				// must ignore AddressSpaceSettingsDefinition
				Address imageBase = mem.getProgram().getImageBase();
				targetSpace = imageBase.getAddressSpace();
				return imageBase.addWrap(addrOffset * targetSpace.getAddressableUnitSize());
			}
			else if (pointerType == PointerType.RELATIVE) {
				// must ignore AddressSpaceSettingsDefinition
				Address base = buf.getAddress();
				targetSpace = base.getAddressSpace();
				return base.addWrap(addrOffset * targetSpace.getAddressableUnitSize());
			}
			else if (pointerType == PointerType.FILE_OFFSET) {
				if (mem == null) {
					errorHandler.accept("Memory not specified");
				}
				else if (mem.getAllFileBytes().size() == 0) {
					errorHandler.accept("No File bytes used");
				}
				else {
					List<Address> addressList = mem.locateAddressesForFileOffset(addrOffset);
					if (addressList.size() == 1) {
						return addressList.get(0);
					}
					if (addressList.size() > 1) {
						errorHandler.accept(
							"Non-unique File offset mapping: 0x" + Long.toHexString(addrOffset));
					}
					else {
						errorHandler.accept(
							"File offset mapping not found: 0x" + Long.toHexString(addrOffset));
					}
				}
				return null;
			}
			else if (pointerType != PointerType.DEFAULT) {
				errorHandler.accept("Unsupported pointer type: " + pointerType.toString());
				return null;
			}

			if (spaceName != null) {
				if (mem == null) {
					errorHandler.accept("Memory not specified");
					return null;
				}
				Program program = mem.getProgram();
				targetSpace = program.getAddressFactory().getAddressSpace(spaceName);
				if (targetSpace == null) {
					errorHandler.accept(
						"Address space not defined: " + spaceName + ":" + formatOffset(addrOffset));
					return null;
				}
			}
			if (targetSpace == null) {
				targetSpace = buf.getAddress().getAddressSpace();
			}

			if (targetSpace instanceof SegmentedAddressSpace) {
				if (size != 2 && size != 4) {
					errorHandler.accept("Unsupported segmented address size: " + size);
					return null;
				}
				if (mask != OffsetMaskSettingsDefinition.DEFAULT || shift != 0) {
					errorHandler.accept("Unsupported mask/shift setting for segmented address");
					return null;
				}
				return getSegmentedAddressValue(buf, size, addrOffset);
			}

			// addrOffset treated as word offset when targetSpace addressable unitsize > 1
			// TODO: May need setting to force treatment as byte-offset
			return targetSpace.getAddress(addrOffset, true);
		}
		catch (IllegalArgumentException | AddressOutOfBoundsException e) {
			errorHandler.accept(e.toString());
		}
		return null;
	}

	private static String formatOffset(long offset) {
		String offsetStr = Long.toHexString(offset);
		int len = offsetStr.length();
		len = len - (len % 4) + 4; // multiple of 4-digits
		return StringUtilities.pad(offsetStr, '0', len);
	}

	/**
	 * Get an offset value based upon bytes stored at the specified buf
	 * location.
	 * 
	 * @param buf         memory buffer and stored pointer location
	 * @param size        store pointer size in bytes
	 * @param signed      true if signed offset or false for unsigned
	 * @return stored offset value or null if unusable buf or data
	 */
	private static Long getStoredOffset(MemBuffer buf, int size, boolean signed,
			Consumer<String> errorHandler) {
		byte[] bytes = new byte[size];
		int cnt = buf.getBytes(bytes, 0);
		if (cnt != size) {
			if (cnt != 0 && errorHandler != null) {
				errorHandler.accept("Insufficient data");
			}
			return null;
		}
		DataConverter converter = DataConverter.getInstance(buf.isBigEndian());
		if (signed) {
			return converter.getSignedValue(bytes, size);
		}
		return converter.getValue(bytes, size);
	}

	/**
	 * Generate an address value based upon bytes stored at the specified buf
	 * location.  The stored bytes will be interpreted as an unsigned byte 
	 * offset into the specified targetSpace.
	 * 
	 * @param buf         memory buffer and stored pointer location
	 * @param size        pointer size in bytes
	 * @param targetSpace address space for returned address
	 * @return address value or null if unusable buf or data
	 */
	public static Address getAddressValue(MemBuffer buf, int size, AddressSpace targetSpace) {

		if (size <= 0 || size > 8) {
			return null;
		}

		Long offset = getStoredOffset(buf, size, false, null);
		if (offset == null) {
			return null; // Insufficient bytes
		}

		if (targetSpace instanceof SegmentedAddressSpace) {
			try {
				// NOTE: conversion assumes a little-endian space
				return getSegmentedAddressValue(buf, size, offset);
			}
			catch (AddressOutOfBoundsException e) {
				// offset too large
			}
			catch (IllegalArgumentException iae) {
				// Do nothing... Tried to create an address that was too large
				// for the address space
				//
				// For example, trying to create a 56 bit pointer in a
				// 32 bit address space.
			}
			return null;
		}

		try {
			return targetSpace.getAddress(offset, true);
		}
		catch (AddressOutOfBoundsException e) {
			// offset too large
		}
		return null;
	}

	/**
	 * Read segmented address from memory. NOTE: little-endian memory assumed.
	 * 
	 * @param buf     memory buffer associated with a segmented-address space
	 *                positioned at start of address value to be read
	 * @param dataLen pointer-length (2 and 4-byte pointers supported)
	 * @return address value returned as segmented Address object or null for
	 *         unsupported pointer length or meory access error occurs.
	 */
	private static Address getSegmentedAddressValue(MemBuffer buf, int dataLen, long storedOffset) {
		SegmentedAddress a = (SegmentedAddress) buf.getAddress();
		int segment = a.getSegment();
		int offset;
		switch (dataLen) {
			case 2: // near pointer
				offset = (int) (storedOffset & 0xffff);
				break;
			case 4: // far pointer
				segment = (int) ((storedOffset >> 16) & 0xffff);
				offset = (int) (storedOffset & 0xffff);
				break;
			default:
				return null;
		}
		SegmentedAddressSpace space = (SegmentedAddressSpace) a.getAddressSpace();
		SegmentedAddress addr = space.getAddress(segment, offset);
		return normalize(addr, buf.getMemory());
	}

	private static SegmentedAddress normalize(SegmentedAddress addr, Memory memory) {
		if (memory == null) {
			return addr;
		}
		MemoryBlock block = memory.getBlock(addr);
		if (block == null) {
			return addr;
		}
		SegmentedAddress start = (SegmentedAddress) block.getStart();
		return addr.normalize(start.getSegment());

	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int len) {

		Address addr = (Address) getValue(buf, settings, len);
		if (addr == null) { // could not create address, so return "Not a pointer (NaP)"
			return NOT_A_POINTER;
		}
		return addr.toString();
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == null) {
			return false;
		}
		if (this == dt) {
			return true;
		}
		if (!(dt instanceof Pointer)) {
			return false;
		}

		Pointer p = (Pointer) dt;
		DataType otherDataType = p.getDataType();
		if (hasLanguageDependantLength() != p.hasLanguageDependantLength()) {
			return false;
		}
		if (!hasLanguageDependantLength() && (getLength() != p.getLength())) {
			return false;
		}
		if (referencedDataType == null) {
			return otherDataType == null;
		}
		if (otherDataType == null) {
			return false;
		}

		// if they contain datatypes that have same ids, then we are essentially
		// equivalent.
		if (DataTypeUtilities.isSameDataType(referencedDataType, otherDataType)) {
			return true;
		}

		if (!DataTypeUtilities.equalsIgnoreConflict(referencedDataType.getPathName(),
			otherDataType.getPathName())) {
			return false;
		}

		// TODO: The pointer deep-dive equivalence checking on the referenced datatype can 
		// cause types containing pointers (composites, functions) to conflict when in
		// reality the referenced type simply has multiple implementations which differ.
		// Although without doing this Ghidra may fail to resolve dependencies which differ
		// from those already contained within a datatype manager.
		// Ghidra's rigid datatype relationships prevent the flexibility to handle 
		// multiple implementations of a named datatype without inducing a conflicted
		// datatype hierarchy.

		if (isEquivalentActive.get()) {
			return true;
		}

		isEquivalentActive.set(true);
		try {
			return getDataType().isEquivalent(otherDataType);
		}
		finally {
			isEquivalentActive.set(false);
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (referencedDataType == dt) {
			notifyDeleted();
			deleted = true;
		}
	}

	@Override
	public boolean isDeleted() {
		return deleted;
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (referencedDataType == oldDt) {
			referencedDataType.removeParent(this);
			referencedDataType = newDt;
			referencedDataType.addParent(this);
			displayName = null;
			String oldName = name;
			name = constructUniqueName(referencedDataType, length);
			notifyNameChanged(oldName);
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		if (referencedDataType == dt) {
			displayName = null;
			name = constructUniqueName(referencedDataType, length);
			notifyNameChanged(oldName);
		}
	}

	@Override
	public CategoryPath getCategoryPath() {
		DataType dt = getDataType();
		if (dt == null) {
			return CategoryPath.ROOT;
		}
		return dt.getCategoryPath();
	}

	@Override
	public boolean dependsOn(DataType dt) {
		if (referencedDataType == null) {
			return false;
		}
		return (referencedDataType == dt || referencedDataType.dependsOn(dt));
	}

	/**
	 * Get a pointer data-type instance with a default size
	 * 
	 * @param dt  data-type referenced by pointer
	 * @param dtm program data-type manager (required) a generic data-type will be
	 *            returned if possible.
	 * @return signed integer data type
	 */
	public static Pointer getPointer(DataType dt, DataTypeManager dtm) {
		return new PointerDataType(dt, dtm);
	}

	/**
	 * Get a pointer data-type instance of the requested size. NOTE: The returned
	 * data-type will not be associated with any particular data-type-manager and
	 * may therefore not utilize dynamically-sized-pointers when a valid pointerSize
	 * is specified. If an invalid pointerSize is specified, a dynamically-size
	 * pointer will be returned whose length is based upon the
	 * default-data-organization.
	 * 
	 * @param dt          data-type referenced by pointer
	 * @param pointerSize pointer size
	 * @return signed integer data type
	 */
	public static Pointer getPointer(DataType dt, int pointerSize) {
// TODO: Need to eliminate all uses of this method !!
		if (pointerSize < 1 || pointerSize > 8) {
			return new PointerDataType(dt);
		}
		return new PointerDataType(dt, pointerSize);
	}

	@Override
	public Pointer newPointer(DataType dt) {
		if (dt != null) {
			dt = dt.clone(getDataTypeManager());
		}
		return new PointerDataType(dt, length, getDataTypeManager());
	}

	@Override
	public String getName() {
		if (referencedDataType != null) {
			// referencedDataType may have had name set, so re-create this pointer name.
			name = constructUniqueName(referencedDataType, length);
		}
		return super.getName();
	}

	@Override
	public String toString() {
		return getName(); // always include pointer length
	}

}
