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

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AlignedStructurePacker.StructurePackResult;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

/**
 * Basic implementation of the structure data type
 */
public class StructureDataType extends CompositeDataTypeImpl implements Structure {
	private final static long serialVersionUID = 1;
	private static Comparator<Object> ordinalComparator = new OrdinalComparator();
	protected static Comparator<Object> offsetComparator = new OffsetComparator();
	protected static Comparator<Object> bitOffsetComparatorLE = new BitOffsetComparator(false);
	protected static Comparator<Object> bitOffsetComparatorBE = new BitOffsetComparator(true);
	protected int structLength;
	protected int numComponents; // excludes optional flexible array component
	protected List<DataTypeComponentImpl> components;
	private DataTypeComponentImpl flexibleArrayComponent;
	private int alignment = -1;

	/**
	 * Construct a new structure with the given name and length.
	 * The root category will be used.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes.  If 0 is specified
	 * the structure will report its length as 1 and {@link #isNotYetDefined()}
	 * will return true.
	 */
	public StructureDataType(String name, int length) {
		this(CategoryPath.ROOT, name, length);
	}

	/**
	 * Construct a new structure with the given name, length and datatype manager 
	 * which conveys data organization.  The root category will be used.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes.  If 0 is specified
	 * the structure will report its length as 1 and {@link #isNotYetDefined()}
	 * will return true.
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not yet contain this actual data type.
	 */
	public StructureDataType(String name, int length, DataTypeManager dtm) {
		this(CategoryPath.ROOT, name, length, dtm);
	}

	/**
	 * Construct a new structure with the given name and length within the
	 * specified categry path.
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes.  If 0 is specified
	 * the structure will report its length as 1 and {@link #isNotYetDefined()}
	 * will return true.
	 */
	public StructureDataType(CategoryPath path, String name, int length) {
		this(path, name, length, null);
	}

	/**
	 * Construct a new structure with the given name, length and datatype manager
	 * within the specified categry path.
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes.  If 0 is specified
	 * the structure will report its length as 1 and {@link #isNotYetDefined()}
	 * will return true.
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not yet contain this actual data type.
	 */
	public StructureDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
		super(path, name, dtm);
		if (length < 0) {
			throw new IllegalArgumentException("Length can't be negative");
		}

		components = new ArrayList<>();
		structLength = length;
		numComponents = length;
	}

	/**
	 * Construct a new structure with the given name and length
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes.  If 0 is specified
	 * the structure will report its length as 1 and {@link #isNotYetDefined()}
	 * will return true.
	 * @param universalID the id for the data type
	 * @param sourceArchive the source archive for this data type
	 * @param lastChangeTime the last time this data type was changed
	 * @param lastChangeTimeInSourceArchive the last time this data type was changed in
	 * its source archive.
	 * @param dtm the data type manager associated with this data type. This can be null. 
	 * Also, the data type manager may not yet contain this actual data type.
	 */
	public StructureDataType(CategoryPath path, String name, int length, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		components = new ArrayList<>();
		structLength = length;
		numComponents = length;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Structure>";
		}
		return "";
	}

	@Override
	public boolean isNotYetDefined() {
		return structLength == 0 && flexibleArrayComponent == null;
	}

	@Override
	public int getAlignment() {
		if (!isInternallyAligned()) {
			return 1; // Unaligned
		}
		if (alignment <= 0) {
			StructurePackResult packResult = AlignedStructureInspector.packComponents(this);
			alignment = packResult.alignment;
		}
		return alignment;
	}

	@Override
	public DataTypeComponent getComponentAt(int offset) {
		if (offset >= structLength || offset < 0) {
			return null;
		}
		int index = Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);
		if (index >= 0) {
			DataTypeComponent dtc = components.get(index);
			if (dtc.isBitFieldComponent()) {
				index = backupToFirstComponentContainingOffset(index, offset);
				dtc = components.get(index);
			}
			return dtc;
		}
		else if (isInternallyAligned()) {
			return null;
		}
		index = -index - 1;
		int ordinal = offset;
		if (index > 0) {
			DataTypeComponent dtc = components.get(index - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
		}
		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		DataTypeComponent dtc = getComponentAt(offset);
		if (dtc != null) {
			DataType dt = dtc.getDataType();
			if (dt instanceof Structure) {
				return ((Structure) dt).getDataTypeAt(offset - dtc.getOffset());
			}
		}
		return dtc;
	}

	@Override
	public int getLength() {
		if (structLength == 0) {
			return 1; // lie about our length if not yet defined
		}
		return structLength;
	}

	@Override
	public void delete(int ordinal) {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(ordinal);
		}
		int idx;
		if (isInternallyAligned()) {
			idx = ordinal;
		}
		else {
			idx = Collections.binarySearch(components, Integer.valueOf(ordinal), ordinalComparator);
		}
		if (idx >= 0) {
			doDelete(idx);
			adjustInternalAlignment();
		}
		else {
			// assume unaligned removal of DEFAULT
			idx = -idx - 1;
			shiftOffsets(idx, -1, -1);
		}
		notifySizeChanged();
	}

	private void doDelete(int index) {
		DataTypeComponentImpl dtc = components.remove(index);
		dtc.getDataType().removeParent(this);
		if (isInternallyAligned()) {
			return;
		}
		int shiftAmount = dtc.isBitFieldComponent() ? 0 : dtc.getLength();
		shiftOffsets(index, -1, -shiftAmount);
	}

	@Override
	public void delete(int[] ordinals) {

		for (int ordinal : ordinals) {
			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
		}

		// delete ordinals in reverse order so that they remain valid
		// during individual deletes
		int[] sortedOrdinals = ordinals.clone();
		Arrays.sort(sortedOrdinals);

		for (int i = sortedOrdinals.length - 1; i >= 0; i--) {
			int ordinal = sortedOrdinals[i];
			int idx;
			if (isInternallyAligned()) {
				idx = ordinal;
			}
			else {
				idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
					ordinalComparator);
			}
			if (idx >= 0) {
				doDelete(idx);
			}
			else {
				// assume unaligned removal of DEFAULT
				idx = -idx - 1;
				shiftOffsets(idx, -1, -1);
			}
		}
		adjustInternalAlignment();
		notifySizeChanged();
	}

	private void shiftOffsets(int index, int deltaOrdinal, int deltaOffset) {
		for (int i = index; i < components.size(); i++) {
			DataTypeComponentImpl dtc = components.get(i);
			shiftOffset(dtc, deltaOrdinal, deltaOffset);
		}
		structLength += deltaOffset;
		numComponents += deltaOrdinal;
	}

	protected void shiftOffset(DataTypeComponentImpl dtc, int deltaOrdinal, int deltaOffset) {
		dtc.setOffset(dtc.getOffset() + deltaOffset);
		dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal);
	}

	@Override
	public DataTypeComponent getComponent(int index) {
		if (index == numComponents && flexibleArrayComponent != null) {
			return flexibleArrayComponent;
		}
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(index), ordinalComparator);
		if (idx >= 0) {
			return components.get(idx);
		}
		// assume unaligned DEFAULT
		int offset = 0;
		idx = -idx - 1;
		if (idx == 0) {
			offset = index;
		}
		else {
			DataTypeComponent dtc = components.get(idx - 1);
			offset = dtc.getEndOffset() + index - dtc.getOrdinal();
		}

		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, index, offset);
	}

	@Override
	public int getNumComponents() {
		return numComponents;
	}

	@Override
	public int getNumDefinedComponents() {
		return components.size();
	}

	@Override
	public final DataTypeComponentImpl insertAtOffset(int offset, DataType dataType, int length) {
		return insertAtOffset(offset, dataType, length, null, null);
	}

	@Override
	public DataTypeComponentImpl insertAtOffset(int offset, DataType dataType, int length,
			String componentName, String comment) throws IllegalArgumentException {

		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}

		if (dataType instanceof BitFieldDataType) {
			BitFieldDataType bfDt = (BitFieldDataType) dataType;
			if (length <= 0) {
				length = dataType.getLength();
			}
			try {
				return insertBitFieldAt(offset, length, bfDt.getBitOffset(), bfDt.getBaseDataType(),
					bfDt.getDeclaredBitSize(), componentName, comment);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e);
			}
		}

		validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		if ((offset > structLength) && !isInternallyAligned()) {
			numComponents = numComponents + (offset - structLength);
			structLength = offset;
		}

		int index = Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);

		int additionalShift = 0;
		if (index >= 0) {
			index = backupToFirstComponentContainingOffset(index, offset);
			DataTypeComponent dtc = components.get(index);
			additionalShift = offset - dtc.getOffset();
		}
		else {
			index = -index - 1;
		}

		int ordinal = offset;
		if (index > 0) {
			DataTypeComponent dtc = components.get(index - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
		}

		if (dataType == DataType.DEFAULT) {
			// assume unaligned insert of DEFAULT
			shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
			return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
		}

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, ordinal,
			offset, componentName, comment);
		dataType.addParent(this);
		shiftOffsets(index, 1 + additionalShift, dtc.getLength() + additionalShift);
		components.add(index, dtc);
		adjustInternalAlignment();
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) {
		return doAdd(dataType, length, false, componentName, comment);
	}

	/**
	 * Add a new component to the end of this structure.
	 * <p>
	 * NOTE: This method differs from inserting to the end the structure for the unaligned
	 * case in that this method will always grow the structure by the positive length 
	 * specified while the insert may limit its growth by the length of a smaller fixed-length
	 * dataType.
	 * @param dataType component data type
	 * @param length maximum component length or -1 to use length of fixed-length dataType 
	 * after applying structures data organization as determined by data type manager.  
	 * If dataType is Dynamic, a positive length must be specified. 
	 * @param isFlexibleArray if true length is ignored and the trailing flexible array will be 
	 * set based upon the specified fixed-length dataType;
	 * @param componentName component name
	 * @param comment componetn comment
	 * @return newly added component
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to be added to this composite data type or an invalid length is specified.
	 */
	private DataTypeComponent doAdd(DataType dataType, int length, boolean isFlexibleArray,
			String componentName, String comment) throws IllegalArgumentException {

		validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		DataTypeComponentImpl dtc;
		if (dataType == DataType.DEFAULT) {
			dtc = new DataTypeComponentImpl(DataType.DEFAULT, this, 1, numComponents, structLength);
		}
		else {

			int offset = structLength;
			int ordinal = numComponents;

			int componentLength;
			if (isFlexibleArray) {
				// assume trailing flexible array component
				offset = -1;
				ordinal = -1;
				clearFlexibleArrayComponent();
				componentLength = 0;
			}
			else {
				componentLength = getPreferredComponentLength(dataType, length);
			}

			dtc = new DataTypeComponentImpl(dataType, this, componentLength, ordinal, offset,
				componentName, comment);
			dataType.addParent(this);
			if (isFlexibleArray) {
				flexibleArrayComponent = dtc;
			}
			else {
				components.add(dtc);
			}
		}
		if (!isFlexibleArray) {

			int structureGrowth = dtc.getLength();
			if (!isInternallyAligned() && length > 0) {
				structureGrowth = length;
			}

			numComponents++;
			structLength += structureGrowth;
		}
		adjustInternalAlignment();
		notifySizeChanged();
		return dtc;
	}

	@Override
	public void growStructure(int amount) {
		numComponents += amount;
		structLength += amount;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	public DataTypeComponent insert(int index, DataType dataType, int length, String componentName,
			String comment) throws ArrayIndexOutOfBoundsException, IllegalArgumentException {
		if (index < 0 || index > numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		if (index == numComponents) {
			return add(dataType, length, componentName, comment);
		}
		validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		int idx;
		if (isInternallyAligned()) {
			idx = index;
		}
		else {
			// TODO: could improve insertion of bitfield which does not intersect
			// existing ordinal bitfield at the bit-level
			idx = Collections.binarySearch(components, Integer.valueOf(index), ordinalComparator);
			if (idx > 0) {
				DataTypeComponentImpl existingDtc = components.get(idx);
				if (existingDtc.isBitFieldComponent()) {
					// must shift down to eliminate possible overlap with previous component 
					DataTypeComponentImpl previousDtc = components.get(idx - 1);
					if (previousDtc.getEndOffset() == existingDtc.getOffset()) {
						shiftOffsets(idx, 0, 1);
					}
				}
			}
		}
		if (idx < 0) {
			idx = -idx - 1;
		}
		if (dataType == DataType.DEFAULT) {
			// assume unaligned insert of DEFAULT
			shiftOffsets(idx, 1, 1);
			return getComponent(index);
		}

		length = getPreferredComponentLength(dataType, length);

		int offset = (getComponent(index)).getOffset();
		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, index, offset,
			componentName, comment);
		dataType.addParent(this);
		shiftOffsets(idx, 1, dtc.getLength());
		components.add(idx, dtc);
		adjustInternalAlignment();
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) throws InvalidDataTypeException {

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(dataMgr);

		BitFieldDataType bitFieldDt = new BitFieldDataType(baseDataType, bitSize);
		return add(bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
	}

	@Override
	public DataTypeComponent insertBitField(int ordinal, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException, ArrayIndexOutOfBoundsException {

		if (ordinal < 0 || ordinal > numComponents) {
			throw new ArrayIndexOutOfBoundsException(ordinal);
		}

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(dataMgr);

		if (!isInternallyAligned()) {
			int offset = structLength;
			if (ordinal < numComponents) {
				offset = getComponent(ordinal).getOffset();
			}
			return insertBitFieldAt(offset, byteWidth, bitOffset, baseDataType, bitSize,
				componentName, comment);
		}

		// handle aligned bitfield insertion
		BitFieldDataType bitFieldDt = new BitFieldDataType(baseDataType, bitSize);
		return insert(ordinal, bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
	}

	@Override
	public DataTypeComponentImpl insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException {

		if (byteOffset < 0 || bitSize < 0) {
			throw new IllegalArgumentException(
				"Negative values not permitted when defining bitfield");
		}
		if (byteWidth <= 0) {
			throw new IllegalArgumentException("Invalid byteWidth");
		}

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(dataMgr);

		int effectiveBitSize =
			BitFieldDataType.getEffectiveBitSize(bitSize, baseDataType.getLength());

		int minByteWidth = BitFieldDataType.getMinimumStorageSize(effectiveBitSize + bitOffset);
		if (byteWidth < minByteWidth) {
			throw new IllegalArgumentException(
				"Bitfield does not fit within specified constraints");
		}

		boolean bigEndian = getDataOrganization().isBigEndian();

		boolean hasConflict = false;
		int additionalShift = 0;

		int startBitOffset = BitOffsetComparator.getNormalizedBitfieldOffset(byteOffset, byteWidth,
			effectiveBitSize, bitOffset, bigEndian);

		Comparator<Object> bitOffsetComparator =
			bigEndian ? bitOffsetComparatorBE : bitOffsetComparatorLE;
		int startIndex = Collections.binarySearch(components, Integer.valueOf(startBitOffset),
			bitOffsetComparator);
		if (startIndex < 0) {
			startIndex = -startIndex - 1;
		}
		else {
			hasConflict = true;
			DataTypeComponentImpl dtc = components.get(startIndex);
			if (bitSize == 0 || dtc.isZeroBitFieldComponent()) {
				hasConflict = dtc.getOffset() != (startBitOffset / 8);
			}
			if (hasConflict) {
				additionalShift = byteOffset - dtc.getOffset();
			}
		}

		int ordinal; // computed ordinal will be adjusted after insertion complete
		if (startIndex < components.size()) {
			DataTypeComponentImpl dtc = components.get(startIndex);
			ordinal = dtc.getOrdinal();
		}
		else {
			ordinal = startIndex;
		}

		if (isInternallyAligned()) {
			insertBitField(ordinal, 0, 0, baseDataType, effectiveBitSize, componentName, comment);
		}

		int endIndex = startIndex;
		if (startIndex < components.size()) {
			// some shifting of components may be required
			int endBitOffset = startBitOffset;
			if (effectiveBitSize != 0) {
				endBitOffset += effectiveBitSize - 1;
			}
			endIndex = Collections.binarySearch(components, Integer.valueOf(endBitOffset),
				bitOffsetComparator);
			if (endIndex < 0) {
				endIndex = -endIndex - 1;
			}
			else if (effectiveBitSize != 0) {
				hasConflict = true;
			}
		}

		if (startIndex != endIndex) {
			hasConflict = true;
		}

		// Any conflict will force a full insertion of byteWidth
		if (hasConflict) {
			shiftOffsets(startIndex, 1, byteWidth + additionalShift);
		}

		int requiredLength = byteOffset + byteWidth;
		if (requiredLength > structLength) {
			structLength = requiredLength;
		}

		// adjust for minimal storage use
		int storageBitOffset = bitOffset % 8;
		int revisedOffset;
		if (bigEndian) {
			revisedOffset = byteOffset + byteWidth - ((effectiveBitSize + bitOffset + 7) / 8);
		}
		else {
			revisedOffset = byteOffset + (bitOffset / 8);
		}

		BitFieldDataType bitfieldDt = new BitFieldDataType(baseDataType, bitSize, storageBitOffset);

		DataTypeComponentImpl dtc = new DataTypeComponentImpl(bitfieldDt, this,
			bitfieldDt.getStorageSize(), ordinal, revisedOffset, componentName, comment);
		bitfieldDt.addParent(this); // currently has no affect

		components.add(startIndex, dtc);
		adjustUnalignedComponents();
		notifySizeChanged();
		return dtc;
	}

	/**
	 * Backup from specified ordinal to the first component which contains
	 * the specified offset.  For normal components the specified
	 * ordinal will be returned, however for bit-fields the ordinal of the first
	 * bit-field containing the specified offset will be returned.
	 * @param ordinal component ordinal
	 * @param offset offset within structure
	 * @return index of first defined component containing specific offset.
	 */
	private int backupToFirstComponentContainingOffset(int index, int offset) {
		if (index == 0) {
			return 0;
		}
		DataTypeComponentImpl dtc = components.get(index);
		while (index != 0 && dtc.isBitFieldComponent()) {
			DataTypeComponentImpl previous = components.get(index - 1);
			if (!previous.containsOffset(offset)) {
				break;
			}
			dtc = previous;
			--index;
		}
		return index;
	}

	/**
	 * Advance from specified ordinal to the last component which contains
	 * the specified offset.  For normal components the specified
	 * ordinal will be returned, however for bit-fields the ordinal of the last
	 * bit-field containing the specified offset will be returned.
	 * @param ordinal component ordinal
	 * @param offset offset within structure
	 * @return index of last defined component containing specific offset.
	 */
	private int advanceToLastComponentContainingOffset(int index, int offset) {
		DataTypeComponentImpl dtc = components.get(index);
		while (index < (components.size() - 1) && dtc.isBitFieldComponent()) {
			DataTypeComponentImpl next = components.get(index + 1);
			if (!next.containsOffset(offset)) {
				break;
			}
			dtc = next;
			++index;
		}
		return index;
	}

	@Override
	public void deleteAtOffset(int offset) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset >= structLength) {
			return;
		}
		int index = Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);

		int offsetDelta = 0;
		int ordinalDelta = 0;
		if (index < 0) {
			index = -index - 1;
			--ordinalDelta;
			offsetDelta = -1;
			shiftOffsets(index, ordinalDelta, offsetDelta);
		}
		else {
			index = advanceToLastComponentContainingOffset(index, offset);
			DataTypeComponentImpl dtc = components.get(index);
			while (dtc.containsOffset(offset)) {
				doDelete(index);
				if (--index < 0) {
					break;
				}
				dtc = components.get(index);
			}
		}

		adjustInternalAlignment();
		notifySizeChanged();
		return;
	}

	@Override
	public boolean isEquivalent(DataType dataType) {

		if (dataType == this) {
			return true;
		}
		if (!(dataType instanceof Structure)) {
			return false;
		}

		Structure struct = (Structure) dataType;
		if (isInternallyAligned() != struct.isInternallyAligned() ||
			isDefaultAligned() != struct.isDefaultAligned() ||
			isMachineAligned() != struct.isMachineAligned() ||
			getMinimumAlignment() != struct.getMinimumAlignment() ||
			getPackingValue() != struct.getPackingValue() ||
			(!isInternallyAligned() && (getLength() != struct.getLength()))) {
			return false;
		}

		DataTypeComponent myFlexComp = getFlexibleArrayComponent();
		DataTypeComponent otherFlexComp = struct.getFlexibleArrayComponent();
		if (myFlexComp != null) {
			if (otherFlexComp == null || !myFlexComp.isEquivalent(otherFlexComp)) {
				return false;
			}
		}
		else if (otherFlexComp != null) {
			return false;
		}

		int myNumComps = getNumComponents();
		int otherNumComps = struct.getNumComponents();
		if (myNumComps != otherNumComps) {
			return false;
		}
		for (int i = 0; i < myNumComps; i++) {
			DataTypeComponent myDtc = getComponent(i);
			DataTypeComponent otherDtc = struct.getComponent(i);

			if (!myDtc.isEquivalent(otherDtc)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (isInternallyAligned()) {
			adjustInternalAlignment();
			return;
		}
		boolean didChange = false;
		int n = components.size();
		for (int i = 0; i < n; i++) {
			DataTypeComponentImpl dtc = components.get(i);
			int nextIndex = i + 1;
			if (dtc.getDataType() == dt) {
				// assume no impact to bitfields since base types 
				// should not change size
				int dtLen = dt.getLength();
				int dtcLen = dtc.getLength();
				if (dtLen < dtcLen) {
					dtc.setLength(dtLen);
					shiftOffsets(nextIndex, dtcLen - dtLen, 0);
					didChange = true;
				}
				else if (dtLen > dtcLen) {
					int consumed = consumeBytesAfter(i, dtLen - dtcLen);
					if (consumed > 0) {
						shiftOffsets(nextIndex, 0 - consumed, 0);
						didChange = true;
					}
				}
			}
		}
		if (didChange) {
			adjustInternalAlignment();
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (isInternallyAligned()) {
			adjustInternalAlignment();
		}
	}

	/**
	 * 
	 * @param index the index of the defined component that is consuming the bytes.
	 * @param numBytes the number of undefined bytes to consume
	 * @return the number of bytes actually consumed
	 */

	private int consumeBytesAfter(int definedComponentIndex, int numBytes) {
		DataTypeComponentImpl thisDtc = components.get(definedComponentIndex);
		int thisLen = thisDtc.getLength();
		int nextOffset = thisDtc.getOffset() + thisLen;
		int available;
		// handle last component differently - allow it to grow the structure if needed
		if (definedComponentIndex == components.size() - 1) {
			available = structLength - nextOffset;
			if (numBytes > available) {
				doGrowStructure(numBytes - available);
				available = numBytes;
			}
		}
		else {
			DataTypeComponent nextDtc = components.get(definedComponentIndex + 1);
			available = nextDtc.getOffset() - nextOffset;
		}

		if (numBytes <= available) {
			thisDtc.setLength(thisLen + numBytes);
			return numBytes;
		}
		thisDtc.setLength(thisLen + available);
		return available;
	}

	/**
	 * Create copy of structure for target dtm (source archive information is discarded).
	 * WARNING! copying unaligned structures which contain bitfields can produce
	 * invalid results when switching endianess due to the differences in packing order.
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public DataType copy(DataTypeManager dtm) {
		StructureDataType struct = new StructureDataType(categoryPath, getName(), getLength(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
	}

	/**
	 * Create cloned structure for target dtm preserving source archive information.
	 * WARNING! cloning unaligned structures which contain bitfields can produce
	 * invalid results when switching endianess due to the differences in packing order.
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		StructureDataType struct =
			new StructureDataType(categoryPath, getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;

	}

	@Override
	public void clearComponent(int index) {
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(index), ordinalComparator);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			dtc.getDataType().removeParent(this);
			int len = dtc.getLength();
			if (len > 1) {
				shiftOffsets(idx, len - 1, 0);
			}
		}
		adjustInternalAlignment();
	}

	/**
	 * Replaces the internal components of this structure with components of the
	 * given structure. 
	 * @param dataType the structure to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types 
	 * are not allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException();
		}

		Structure struct = (Structure) dataType;

		int oldLength = structLength;

		components.clear();
		structLength = 0;
		numComponents = 0;
		flexibleArrayComponent = null;

		setAlignment(struct);

		if (struct.isInternallyAligned()) {
			doReplaceWithAligned(struct);
		}
		else {
			doReplaceWithUnaligned(struct);
		}

		DataTypeComponent flexComponent = struct.getFlexibleArrayComponent();
		if (flexComponent != null) {
			setFlexibleArrayComponent(flexComponent.getDataType(), flexComponent.getFieldName(),
				flexComponent.getComment());
		}

		if (oldLength != structLength) {
			notifySizeChanged();
		}
	}

	private void doReplaceWithAligned(Structure struct) {
		// assumes components is clear and that alignment characteristics have been set
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			DataType dt = dtc.getDataType();
			int length = (dt instanceof Dynamic) ? dtc.getLength() : -1;
			add(dt, length, dtc.getFieldName(), dtc.getComment());
		}
	}

	private void doReplaceWithUnaligned(Structure struct) throws IllegalArgumentException {
		// assumes components is clear and that alignment characteristics have been set.
		if (struct.isNotYetDefined()) {
			return;
		}

		structLength = struct.getLength();
		numComponents = structLength;

		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];

			DataType dt = dtc.getDataType().clone(dataMgr);
			checkAncestry(dt);

			int length = getPreferredComponentLength(dt, dtc.getLength());

			components.add(new DataTypeComponentImpl(dt, this, length, dtc.getOrdinal(),
				dtc.getOffset(), dtc.getFieldName(), dtc.getComment()));
		}
		adjustComponents();
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		boolean didChange = false;
		if (flexibleArrayComponent != null && flexibleArrayComponent.getDataType() == dt) {
			flexibleArrayComponent.getDataType().removeParent(this);
			flexibleArrayComponent = null;
			didChange = true;
		}
		int n = components.size();
		for (int i = n - 1; i >= 0; i--) {
			DataTypeComponentImpl dtc = components.get(i);
			boolean removeBitFieldComponent = false;
			if (dtc.isBitFieldComponent()) {
				BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
				removeBitFieldComponent = bitfieldDt.getBaseDataType() == dt;
			}
			if (removeBitFieldComponent || dtc.getDataType() == dt) {
				dt.removeParent(this);
				components.remove(i);
				shiftOffsets(i, dtc.getLength() - 1, 0);
				didChange = true;
			}
		}
		if (didChange) {
			adjustInternalAlignment();
			notifySizeChanged();
		}
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType replacementDt)
			throws IllegalArgumentException {
		DataType newDt = replacementDt;
		try {
			validateDataType(replacementDt);
			if (replacementDt.getDataTypeManager() != dataMgr) {
				replacementDt = replacementDt.clone(dataMgr);
			}
			checkAncestry(replacementDt);
		}
		catch (Exception e) {
			// TODO: should we use Undefined1 instead to avoid cases where
			// DEFAULT datatype can not be used (flex array, bitfield, aligned structure)
			// TODO: failing silently is rather hidden
			replacementDt = DataType.DEFAULT;
		}

		boolean changed = false;
		if (flexibleArrayComponent != null && flexibleArrayComponent.getDataType() == oldDt) {
			flexibleArrayComponent.getDataType().removeParent(this);
			if (isInvalidFlexArrayDataType(replacementDt)) {
				flexibleArrayComponent = null;
				Msg.error(this, "Invalid flex array replacement type " + newDt.getName() +
					", removing flex array: " + getPathName());
			}
			else {
				flexibleArrayComponent.setDataType(replacementDt);
				replacementDt.addParent(this);
			}
			changed = true;
		}

		for (int i = components.size() - 1; i >= 0; i--) {

			DataTypeComponentImpl comp = components.get(i);
			int nextIndex = i + 1;

			boolean remove = false;
			if (comp.isBitFieldComponent()) {
				try {
					changed |= updateBitFieldDataType(comp, oldDt, replacementDt);
				}
				catch (InvalidDataTypeException e) {
					Msg.error(this,
						"Invalid bitfield replacement type " + newDt.getName() +
							", removing bitfield " + comp.getDataType().getName() + ": " +
							getPathName());
					remove = true;
				}
			}
			else if (comp.getDataType() == oldDt) {
				if (replacementDt == DEFAULT && isInternallyAligned()) {
					Msg.error(this,
						"Invalid replacement type " + newDt.getName() + ", removing component " +
							comp.getDataType().getName() + ": " + getPathName());
					remove = true;
				}
				else {
					setComponentDataType(comp, replacementDt, nextIndex);
					changed = true;
				}
			}
			if (remove) {
				// error case - remove component
				oldDt.removeParent(this);
				components.remove(i);
				shiftOffsets(i, comp.getLength() - 1, 0); // ordinals only
				changed = true;
			}
		}

		if (changed) {
			adjustInternalAlignment();
			notifySizeChanged();
		}
	}

	private void setComponentDataType(DataTypeComponentImpl comp, DataType newDt, int nextIndex) {
		comp.getDataType().removeParent(this);
		comp.setDataType(newDt);
		newDt.addParent(this);
		int len = newDt.getLength();
		int oldLen = comp.getLength();
		if (len > 0) {
			if (len < oldLen) {
				comp.setLength(len);
				shiftOffsets(nextIndex, oldLen - len, 0);
			}
			else if (len > oldLen) {
				int bytesAvailable = getNumUndefinedBytes(comp.getOrdinal() + 1);
				int bytesNeeded = len - oldLen;
				if (bytesNeeded <= bytesAvailable) {
					comp.setLength(len);
					shiftOffsets(nextIndex, -bytesNeeded, 0);
				}
				else if (comp.getOrdinal() == getLastDefinedComponentIndex()) { // we are the last defined component, grow structure
					doGrowStructure(bytesNeeded - bytesAvailable);
					comp.setLength(len);
					shiftOffsets(nextIndex, -bytesNeeded, 0);
				}
				else {
					comp.setLength(oldLen + bytesAvailable);
					shiftOffsets(nextIndex, -bytesAvailable, 0);
				}
			}
		}
	}

	@Override
	public DataTypeComponent[] getDefinedComponents() {
		return components.toArray(new DataTypeComponent[components.size()]);
	}

	@Override
	public DataTypeComponent[] getComponents() {
		DataTypeComponent[] comps = new DataTypeComponent[numComponents];
		for (int i = 0; i < comps.length; i++) {
			comps[i] = getComponent(i);
		}
		return comps;
	}

	@Override
	public DataTypeComponent replace(int index, DataType dataType, int length, String componentName,
			String comment) throws ArrayIndexOutOfBoundsException, IllegalArgumentException {
		if (index < 0 || index >= numComponents) {
			throw new ArrayIndexOutOfBoundsException(index);
		}

		validateDataType(dataType);

		DataTypeComponentImpl origDtc = (DataTypeComponentImpl) getComponent(index);
		if (origDtc.isBitFieldComponent()) {
			throw new IllegalArgumentException("Bit-field component may not be directly replaced");
		}

		if (dataType == DataType.DEFAULT) {
			clearComponent(index);
			return getComponent(index);
		}

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponent replacement =
			replaceComponent(origDtc, dataType, length, componentName, comment);
		adjustInternalAlignment();
		return replacement;
	}

	@Override
	public final DataTypeComponent replace(int index, DataType dataType, int length) {
		return replace(index, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length,
			String componentName, String comment) throws IllegalArgumentException {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset >= structLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is beyond end of structure (" + structLength + ").");
		}

		validateDataType(dataType);

		DataTypeComponentImpl origDtc = (DataTypeComponentImpl) getComponentAt(offset);
		if (origDtc.isBitFieldComponent()) {
			throw new IllegalArgumentException("Bit-field component may not be directly replaced");
		}

		if (dataType == DataType.DEFAULT) {
			int ordinal = origDtc.getOrdinal();
			clearComponent(ordinal);
			return getComponent(ordinal);
		}

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponent replacement =
			replaceComponent(origDtc, dataType, length, componentName, comment);

		adjustInternalAlignment();
		return replacement;
	}

	/**
	 * Replace the indicated component with a new component containing the 
	 * specified data type.
	 * @param origDtc the original data type component in this structure.
	 * @param dataType the data type of the new component
	 * @param length the length of the new component
	 * @param componentName the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if the new component couldn't fit.
	 * @throws IllegalArgumentException if the specified data type is not 
	 * allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic 
	 * dependency.  In addition, any attempt to replace an existing bit-field
	 * component or specify a {@link BitFieldDatatype} will produce this error.
	 */
	private DataTypeComponent replaceComponent(DataTypeComponentImpl origDtc, DataType dataType,
			int length, String componentName, String comment) {

// FIXME: Unsure how o support replace operation with bit-fields.  Within unaligned structure 
// the packing behavior for bit-fields prevents a one-for-one replacement and things may shift
// around which the unaligned structure tries to avoid.  Insert and delete are less of a concern
// since movement already can occur, although insert at offset may not retain the offset if it 
// interacts with bit-fields.

		int ordinal = origDtc.getOrdinal();
		int newOffset = origDtc.getOffset();
		int dtcLength = origDtc.getLength();

		DataTypeComponentImpl newDtc = new DataTypeComponentImpl(dataType, this, length, ordinal,
			newOffset, componentName, comment);

		int bytesNeeded = length - dtcLength;
		int deltaOrdinal = -bytesNeeded;
		if (bytesNeeded > 0) {
			int bytesAvailable = getNumUndefinedBytes(ordinal + 1);
			if (bytesAvailable < bytesNeeded) {
				if (ordinal == getLastDefinedComponentIndex()) {
					growStructure(bytesNeeded - bytesAvailable);
				}
				else {
					throw new IllegalArgumentException("Not enough undefined bytes to fit " +
						dataType.getPathName() + " in structure " + getPathName() +
						" at offset 0x" + Integer.toHexString(newOffset) + "." + " It needs " +
						(bytesNeeded - bytesAvailable) + " more byte(s) to be able to fit.");
				}
			}
		}
		int index =
			Collections.binarySearch(components, Integer.valueOf(ordinal), ordinalComparator);
		if (index < 0) {
			index = -index - 1;
		}
		else {
			components.remove(index);
			origDtc.getDataType().removeParent(this);
		}
		components.add(index, newDtc);
		dataType.addParent(this);
		if (deltaOrdinal != 0) {
			shiftOffsets(index + 1, deltaOrdinal, 0);
		}
		return newDtc;
	}

	private int getLastDefinedComponentIndex() {
		if (components.size() == 0) {
			return 0;
		}
		DataTypeComponent dataTypeComponent = components.get(components.size() - 1);
		return dataTypeComponent.getOrdinal();
	}

	/**
	 * Gets the number of Undefined bytes beginning at the indicated component 
	 * index. Undefined bytes that have a field name or comment specified are 
	 * also included.
	 * @param index the component index to begin checking at.
	 * @return the number of contiguous undefined bytes
	 */
	protected int getNumUndefinedBytes(int index) {
		if (index >= numComponents) {
			return 0;
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(index), ordinalComparator);
		DataTypeComponent dtc = null;
		if (idx < 0) {
			idx = -idx - 1;
			if (idx >= components.size()) {
				return numComponents - index;
			}
			dtc = components.get(idx);
			return dtc.getOrdinal() - index;
		}
		return 0;

	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	@Override
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public void deleteAll() {
		for (int i = 0; i < components.size(); i++) {
			DataTypeComponent dtc = components.get(i);
			dtc.getDataType().removeParent(this);
		}
		components.clear();
		structLength = 0;
		numComponents = 0;
		flexibleArrayComponent = null;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public void realign() {
		adjustInternalAlignment();
	}

	@Override
	public void pack(int packingSize) {
		setPackingValue(packingSize);
	}

	/**
	 * Adjust the alignment, packing and padding of components within this structure based upon the 
	 * current alignment and packing attributes for this structure. This method should be 
	 * called to fix up the layout of the internal components of the structure 
	 * after other code has changed the attributes of the structure.
	 * <BR>When switching between internally aligned and unaligned this method corrects the 
	 * component ordinal numbering also.
	 * @return true if the structure was changed by this method.
	 */
	protected boolean adjustComponents() {

		int oldLength = structLength;

		boolean changed = false;
		alignment = -1;

		if (!isInternallyAligned()) {
			changed |= adjustUnalignedComponents();
			if (changed) {
				if (oldLength != structLength) {
					notifySizeChanged();
				}
			}
			return changed;
		}

		StructurePackResult packResult = AlignedStructurePacker.packComponents(this, components);
		changed = packResult.componentsChanged;

		// Adjust the structure
		changed |= updateComposite(packResult.numComponents, packResult.structureLength,
			packResult.alignment);

		if (changed) {
			if (oldLength != structLength) {
				notifySizeChanged();
			}
			return true;
		}
		return false;
	}

	private boolean adjustUnalignedComponents() {
		boolean changed = false;
		int componentCount = 0;
		int currentOffset = 0;
		for (DataTypeComponentImpl dataTypeComponent : components) {
			int componentLength = dataTypeComponent.getLength();
			int componentOffset = dataTypeComponent.getOffset();
			int numUndefinedsBefore = componentOffset - currentOffset;
			if (numUndefinedsBefore > 0) {
				componentCount += numUndefinedsBefore;
			}
			currentOffset = componentOffset + componentLength;
			if (dataTypeComponent.getOrdinal() != componentCount) {
				dataTypeComponent.setOrdinal(componentCount);
				changed = true;
			}
			componentCount++;
		}
		int numUndefinedsAfter = structLength - currentOffset;
		componentCount += numUndefinedsAfter;
		if (updateComposite(componentCount, structLength, 1)) {
			changed = true;
		}
		return changed;
	}

	private boolean updateComposite(int currentNumComponents, int currentLength,
			int currentAlignment) {
		boolean compositeChanged = false;
		if (numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			compositeChanged = true;
		}
		if (structLength != currentLength) {
			structLength = currentLength;
			compositeChanged = true;
		}
		if (alignment != currentAlignment) {
			alignment = currentAlignment;
			compositeChanged = true;
		}
		return compositeChanged;
	}

	private void doGrowStructure(int amount) {
		if (!isInternallyAligned()) {
			numComponents += amount;
		}
		structLength += amount;
	}

	@Override
	public void adjustInternalAlignment() {
		adjustComponents();
	}

	@Override
	public boolean hasFlexibleArrayComponent() {
		return flexibleArrayComponent != null;
	}

	@Override
	public DataTypeComponent getFlexibleArrayComponent() {
		return flexibleArrayComponent;
	}

	private boolean isInvalidFlexArrayDataType(DataType dataType) {
		return (dataType == null || dataType == DataType.DEFAULT ||
			dataType instanceof BitFieldDataType || dataType instanceof Dynamic ||
			dataType instanceof FactoryDataType);
	}

	@Override
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) {
		if (isInvalidFlexArrayDataType(flexType)) {
			throw new IllegalArgumentException(
				"Unsupported flexType: " + flexType.getDisplayName());
		}
		return doAdd(flexType, 0, true, name, comment);
	}

	@Override
	public void clearFlexibleArrayComponent() {
		if (flexibleArrayComponent == null) {
			return;
		}
		flexibleArrayComponent = null;
		adjustInternalAlignment();
		notifySizeChanged();
	}

	@Override
	protected void dumpComponents(StringBuilder buffer, String pad) {
		super.dumpComponents(buffer, pad);
		DataTypeComponent dtc = getFlexibleArrayComponent();
		if (dtc != null) {
			DataType dataType = dtc.getDataType();
			buffer.append(pad + dataType.getDisplayName() + "[0]");
			buffer.append(pad + dtc.getLength());
			buffer.append(pad + dtc.getFieldName());
			String comment = dtc.getComment();
			if (comment == null) {
				comment = "";
			}
			buffer.append(pad + "\"" + comment + "\"");
			buffer.append("\n");
		}
	}
}
