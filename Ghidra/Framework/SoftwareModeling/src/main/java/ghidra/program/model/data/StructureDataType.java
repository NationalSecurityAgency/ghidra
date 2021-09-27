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
 * Basic implementation of the structure data type.
 * NOTES: 
 * <ul>
 * <li>Implementation is not thread safe when being modified.</li>
 * <li>For a structure to treated as having a zero-length (see {@link #isZeroLength()}) it 
 * 
 * </ul>
 * 
 */
public class StructureDataType extends CompositeDataTypeImpl implements StructureInternal {

	protected int structLength;
	private int structAlignment;

	protected int numComponents;
	protected List<DataTypeComponentImpl> components;

	/**
	 * Construct a new structure with the given name and length. The root category will be used.
	 * 
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes. If 0 is specified the structure
	 *            will report its length as 1 and {@link #isNotYetDefined()} will return true.
	 */
	public StructureDataType(String name, int length) {
		this(CategoryPath.ROOT, name, length);
	}

	/**
	 * Construct a new structure with the given name, length and datatype manager which conveys data
	 * organization. The root category will be used.
	 * 
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes. If 0 is specified the structure
	 *            will report its length as 1 and {@link #isNotYetDefined()} will return true.
	 * @param dtm the data type manager associated with this data type. This can be null. Also, the
	 *            data type manager may not yet contain this actual data type.
	 */
	public StructureDataType(String name, int length, DataTypeManager dtm) {
		this(CategoryPath.ROOT, name, length, dtm);
	}

	/**
	 * Construct a new structure with the given name and length within the specified categry path.
	 * 
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes. If 0 is specified the structure
	 *            will report its length as 1 and {@link #isNotYetDefined()} will return true.
	 */
	public StructureDataType(CategoryPath path, String name, int length) {
		this(path, name, length, null);
	}

	/**
	 * Construct a new structure with the given name, length and datatype manager within the
	 * specified categry path.
	 * 
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes. If 0 is specified the structure
	 *            will report its length as 1 and {@link #isNotYetDefined()} will return true.
	 * @param dtm the data type manager associated with this data type. This can be null. Also, the
	 *            data type manager may not yet contain this actual data type.
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
	 * 
	 * @param path the category path indicating where this data type is located.
	 * @param name the name of the new structure
	 * @param length the initial size of the structure in bytes. If 0 is specified the structure
	 *            will report its length as 1 and {@link #isNotYetDefined()} will return true.
	 * @param universalID the id for the data type
	 * @param sourceArchive the source archive for this data type
	 * @param lastChangeTime the last time this data type was changed
	 * @param lastChangeTimeInSourceArchive the last time this data type was changed in its source
	 *            archive.
	 * @param dtm the data type manager associated with this data type. This can be null. Also, the
	 *            data type manager may not yet contain this actual data type.
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
	public int getAlignment() {
		if (structAlignment > 0) {
			return structAlignment;
		}
		if (isPackingEnabled()) {
			StructurePackResult packResult = AlignedStructureInspector.packComponents(this);
			structAlignment = packResult.alignment;
		}
		else {
			structAlignment = getNonPackedAlignment();
		}
		return structAlignment;
	}

	@Override
	public DataTypeComponent getDefinedComponentAtOrAfterOffset(int offset) {
		if (offset > structLength || offset < 0) {
			return null;
		}
		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);
		if (index >= 0) {
			DataTypeComponent dtc = components.get(index);
			index = backupToFirstComponentContainingOffset(index, offset);
			dtc = components.get(index);
			return dtc;
		}
		index = -index - 1;
		if (index < components.size()) {
			return components.get(index);
		}
		return null;
	}

	@Override
	public DataTypeComponent getComponentContaining(int offset) {
		if (offset > structLength || offset < 0) {
			return null;
		}
		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);
		if (index >= 0) {
			// return first matching defined component containing offset
			DataTypeComponent dtc = components.get(index);
			index = indexOfFirstNonZeroLenComponentContainingOffset(index, offset);
			dtc = components.get(index);
			if (dtc.getLength() != 0) {
				return dtc;
			}
			index = -index - 1;
		}

		if (offset != structLength && !isPackingEnabled()) {
			// return undefined component for padding offset within non-packed structure
			return generateUndefinedComponent(offset, index);
		}
		return null;
	}
	
	@Override
	public List<DataTypeComponent> getComponentsContaining(int offset) {
		ArrayList<DataTypeComponent> list = new ArrayList<>();
		if (offset > structLength || offset < 0) {
			return list;
		}
		int index =
			Collections.binarySearch(components, Integer.valueOf(offset),
				OffsetComparator.INSTANCE);

		boolean hasSizedComponent = false;
		if (index >= 0) {
			// collect matching defined components containing offset
			DataTypeComponentImpl dtc = components.get(index);
			index = backupToFirstComponentContainingOffset(index, offset);
			while (index < components.size()) {
				dtc = components.get(index);
				if (!dtc.containsOffset(offset)) {
					break;
				}
				++index;
				hasSizedComponent |= (dtc.getLength() != 0);
				list.add(dtc);
			}
			// transform index for use with generateUndefinedComponent if invoked
			index = -index - 1;
		}

		if (!hasSizedComponent && offset != structLength && !isPackingEnabled()) {
			// generate undefined componentfor padding offset within non-packed structure
			// if offset only occupied by zero-length component
			list.add(generateUndefinedComponent(offset, index));
		}
		return list;
	}

	/**
	 * Generate an undefined component following a binary search across the defined components.
	 * @param offset the offset within this structure which was searched for
	 * @param missingComponentIndex the defined component binary search index result (must be negative)
	 * @return undefined component 
	 */
	private DataTypeComponentImpl generateUndefinedComponent(int offset,
			int missingComponentIndex) {
		if (missingComponentIndex >= 0) {
			throw new AssertException();
		}
		missingComponentIndex = -missingComponentIndex - 1;
		int ordinal = offset;
		if (missingComponentIndex > 0) {
			// compute ordinal from previous defined component
			DataTypeComponent dtc = components.get(missingComponentIndex - 1);
			ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
			if (dtc.getLength() == 0) {
				ordinal += 1;
			}
		}
		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		DataTypeComponent dtc = getComponentContaining(offset);
		if (dtc != null) {
			DataType dt = dtc.getDataType();
			if (dt instanceof Structure) {
				return ((Structure) dt).getDataTypeAt(offset - dtc.getOffset());
			}
		}
		return dtc;
	}

	@Override
	public boolean isZeroLength() {
		return structLength == 0;
	}

	@Override
	public int getLength() {
		if (structLength == 0) {
			return 1; // positive length required
		}
		return structLength;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return isPackingEnabled();
	}

	@Override
	public void delete(int ordinal) {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		int idx;
		if (isPackingEnabled()) {
			idx = ordinal;
		}
		else {
			idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
				OrdinalComparator.INSTANCE);
		}
		if (idx >= 0) {
			doDeleteWithComponentShift(idx, false);
		}
		else {
			// assume non-packed removal of DEFAULT
			idx = -idx - 1;
			shiftOffsets(idx, -1, -1);
		}
		repack(false);
		notifySizeChanged();
	}

	/**
	 * Removes a defined component at the specified index without
	 * any alteration to other components. 
	 * @param index defined component index
	 * @return the defined component which was removed.
	 */
	private DataTypeComponentImpl doDelete(int index) {
		DataTypeComponentImpl dtc = components.remove(index);
		dtc.getDataType().removeParent(this);
		return dtc;
	}

	/**
	 * Removes a defined component at the specified index.
	 * If this corresponds to a zero-length or bit-field component it will 
	 * be cleared without an offset shift to the remaining components.  Removal of
	 * other component types will result in an offset and ordinal shift
	 * to the remaining components.
	 * @param index defined component index
	 * @param disableOffsetShift if false, and component is not a bit-field, an offset shift
	 * and possible structure length change will be performed for non-packed structure.
	 */
	private void doDeleteWithComponentShift(int index, boolean disableOffsetShift) {
		DataTypeComponentImpl dtc = doDelete(index);
		if (isPackingEnabled()) {
			return;
		}
		int shiftAmount = (disableOffsetShift || dtc.isBitFieldComponent()) ? 0 : dtc.getLength();
		shiftOffsets(index, -1, -shiftAmount);
	}

	@Override
	public void delete(Set<Integer> ordinals) {

		if (ordinals.isEmpty()) {
			return;
		}

		boolean bitFieldRemoved = false;

		TreeSet<Integer> treeSet = null;
		if (!isPackingEnabled()) {
			// treeSet only used to track undefined filler removal
			treeSet = new TreeSet<>(ordinals);
		}

		List<DataTypeComponentImpl> newComponents = new ArrayList<>();
		int ordinalAdjustment = 0;
		int offsetAdjustment = 0;
		int lastDefinedOrdinal = -1;
		for (DataTypeComponentImpl dtc : components) {
			int ordinal = dtc.getOrdinal();
			if (treeSet != null && lastDefinedOrdinal < (ordinal - 1)) {
				// Identify removed filler since last defined component
				Set<Integer> removedFillerSet = treeSet.subSet(lastDefinedOrdinal + 1, ordinal);
				if (!removedFillerSet.isEmpty()) {
					int undefinedRemoveCount = removedFillerSet.size();
					ordinalAdjustment -= undefinedRemoveCount;
					offsetAdjustment -= undefinedRemoveCount;
				}
			}
			if (ordinals.contains(ordinal)) {
				// defined component removed
				if (dtc.isBitFieldComponent()) {
					// defer reconciling bitfield space to repack
					bitFieldRemoved = true;
				}
				else {
					offsetAdjustment -= dtc.getLength();
				}
				--ordinalAdjustment;
				lastDefinedOrdinal = ordinal;
			}
			else {

				if (ordinalAdjustment != 0) {
					shiftOffset(dtc, ordinalAdjustment, offsetAdjustment);
				}
				newComponents.add(dtc);
				lastDefinedOrdinal = ordinal;
			}
		}
		if (treeSet != null) {
			// Identify removed filler after last defined component
			Set<Integer> removedFillerSet = treeSet.subSet(lastDefinedOrdinal + 1, numComponents);
			if (!removedFillerSet.isEmpty()) {
				int undefinedRemoveCount = removedFillerSet.size();
				ordinalAdjustment -= undefinedRemoveCount;
				offsetAdjustment -= undefinedRemoveCount;
			}
		}

		components = newComponents;
		numComponents += ordinalAdjustment;

		if (isPackingEnabled()) {
			repack(true);
		}
		else {
			structLength += offsetAdjustment;
			if (bitFieldRemoved) {
				repack(false);
			}
			notifySizeChanged();
		}
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
	public DataTypeComponentImpl getComponent(int ordinal) {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		int index = Collections.binarySearch(components, Integer.valueOf(ordinal),
			OrdinalComparator.INSTANCE);
		if (index >= 0) {
			return components.get(index);
		}
		// assume non-packed DEFAULT
		int offset = 0;
		index = -index - 1;
		if (index == 0) {
			offset = ordinal;
		}
		else {
			DataTypeComponent dtc = components.get(index - 1);
			offset = dtc.getEndOffset() + ordinal - dtc.getOrdinal();
			if (dtc.getLength() == 0) {
				--offset;
			}
		}

		return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
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

		dataType = validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		if ((offset > structLength) && !isPackingEnabled()) {
			numComponents += offset - structLength;
			structLength = offset;
		}

		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);

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
			// assume non-packed insert of DEFAULT
			shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
			return new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
		}

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, ordinal,
			offset, componentName, comment);
		dataType.addParent(this);
		shiftOffsets(index, 1 + additionalShift, length + additionalShift);
		components.add(index, dtc);
		repack(false);
		notifySizeChanged();
		return dtc;
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) {
		return doAdd(dataType, length, componentName, comment, true);
	}

	/**
	 * Add a new component to the end of this structure.
	 * <p>
	 * NOTE: This method differs from inserting to the end the structure for the non-packed case in
	 * that this method will always grow the structure by the positive length specified while the
	 * insert may limit its growth by the length of a smaller fixed-length dataType.
	 * 
	 * @param dataType component data type
	 * @param length maximum component length or -1 to use length of fixed-length dataType after
	 *            applying structures data organization as determined by data type manager. If
	 *            dataType is Dynamic, a positive length must be specified.
	 * @param componentName component name
	 * @param comment component comment
	 * @param packAndNotify if true perform repack and provide change notification
	 * @return newly added component
	 * @throws IllegalArgumentException if the specified data type is not allowed to be added to
	 *             this composite data type or an invalid length is specified.
	 */
	private DataTypeComponent doAdd(DataType dataType, int length, String componentName,
			String comment, boolean packAndNotify)
			throws IllegalArgumentException {

		dataType = validateDataType(dataType);

		dataType = dataType.clone(dataMgr);

		checkAncestry(dataType);

		DataTypeComponentImpl dtc;
		if (dataType == DataType.DEFAULT) {
			// assume non-packed structure - structre will grow by 1-byte below
			dtc = new DataTypeComponentImpl(DataType.DEFAULT, this, 1, numComponents, structLength);
		}
		else {

			int offset = structLength;
			int ordinal = numComponents;

			int componentLength = getPreferredComponentLength(dataType, length);

			dtc = new DataTypeComponentImpl(dataType, this, componentLength, ordinal, offset,
				componentName, comment);
			dataType.addParent(this);
			components.add(dtc);
		}

		int structureGrowth = dtc.getLength();
		if (structureGrowth != 0 && !isPackingEnabled() && length > 0) {
			structureGrowth = length;
		}

		numComponents++;
		structLength += structureGrowth;

		if (packAndNotify) {
			repack(false);
			notifySizeChanged();
		}
		return dtc;
	}

	@Override
	public void growStructure(int amount) {
		if (isPackingEnabled()) {
			return;
		}
		doGrowStructure(amount);
		repack(false);
		notifySizeChanged();
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String componentName,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException {
		if (ordinal < 0 || ordinal > numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		if (ordinal == numComponents) {
			return add(dataType, length, componentName, comment);
		}
		dataType = validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		int idx;
		if (isPackingEnabled()) {
			idx = ordinal;
		}
		else {
			// TODO: could improve insertion of bitfield which does not intersect
			// existing ordinal bitfield at the bit-level
			idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
				OrdinalComparator.INSTANCE);
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
			// assume non-packed insert of DEFAULT
			shiftOffsets(idx, 1, 1);
			return getComponent(ordinal);
		}

		length = getPreferredComponentLength(dataType, length);

		int offset = (getComponent(ordinal)).getOffset();
		DataTypeComponentImpl dtc = new DataTypeComponentImpl(dataType, this, length, ordinal, offset,
			componentName, comment);
		dataType.addParent(this);
		shiftOffsets(idx, 1, dtc.getLength());
		components.add(idx, dtc);
		repack(false);
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
			throws InvalidDataTypeException, IndexOutOfBoundsException {

		if (ordinal < 0 || ordinal > numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(dataMgr);

		if (!isPackingEnabled()) {
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
			bigEndian ? BitOffsetComparator.INSTANCE_BE : BitOffsetComparator.INSTANCE_LE;
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

		if (isPackingEnabled()) {
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
		adjustNonPackedComponents();
		notifySizeChanged();
		return dtc;
	}

	/**
	 * Backup from specified defined-component index to the first component which contains the specified offset. 
	 * @param index any defined component index which contains offset
	 * @param offset offset within structure
	 * @return index of first defined component containing specific offset.
	 */
	private int backupToFirstComponentContainingOffset(int index, int offset) {
		if (index == 0) {
			return 0;
		}
		while (index != 0) {
			DataTypeComponentImpl previous = components.get(index - 1);
			if (!previous.containsOffset(offset)) {
				break;
			}
			--index;
		}
		return index;
	}

	/**
	 * Identify defined-component index of the first non-zero-length component which contains the specified offset.
	 * If only zero-length components exist, the last zero-length component which contains the offset will be returned. 
	 * @param index any defined component index which contains offset
	 * @param offset offset within structure
	 * @return index of first defined component containing specific offset.
	 */
	private int indexOfFirstNonZeroLenComponentContainingOffset(int index, int offset) {
		index = backupToFirstComponentContainingOffset(index, offset);
		DataTypeComponentImpl next = components.get(index);
		while (next.getLength() == 0 && index < (components.size() - 1)) {
			next = components.get(index + 1);
			if (!next.containsOffset(offset)) {
				break;
			}
			++index;
		}
		return index;
	}

	/**
	 * Advance from specified defined-component index to the last component which contains the specified offset.
	 * @param index any defined component index which contains offset
	 * @param offset offset within structure
	 * @return index of last defined component containing specific offset.
	 */
	private int advanceToLastComponentContainingOffset(int index, int offset) {
		while (index < (components.size() - 1)) {
			DataTypeComponentImpl next = components.get(index + 1);
			if (!next.containsOffset(offset)) {
				break;
			}
			++index;
		}
		return index;
	}

	@Override
	public void deleteAtOffset(int offset) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset > structLength) {
			return;
		}

		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);

		if (index < 0) {
			if (offset == structLength) {
				return;
			}
			shiftOffsets(-index - 1, -1, -1);
		}
		else {
			// delete all components containing offset working backward from last such component
			index = advanceToLastComponentContainingOffset(index, offset);
			DataTypeComponentImpl dtc = components.get(index);
			while (dtc.containsOffset(offset)) {
				doDeleteWithComponentShift(index, false);
				if (--index < 0) {
					break;
				}
				dtc = components.get(index);
			}
		}
		repack(false);
		notifySizeChanged();
	}

	@Override
	public void clearAtOffset(int offset) {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset > structLength) {
			return;
		}

		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);
		if (index < 0) {
			return;
		}

		// clear all components containing offset working backward from last such component
		index = advanceToLastComponentContainingOffset(index, offset);
		DataTypeComponentImpl dtc = components.get(index);
		while (dtc.containsOffset(offset)) {
			doDeleteWithComponentShift(index, true); // updates timestamp
			if (--index < 0) {
				break;
			}
			dtc = components.get(index);
		}

		repack(false);
		notifySizeChanged();
	}

	@Override
	public boolean isEquivalent(DataType dataType) {

		if (dataType == this) {
			return true;
		}
		if (!(dataType instanceof StructureInternal)) {
			return false;
		}

		StructureInternal struct = (StructureInternal) dataType;
		int otherLength = struct.isZeroLength() ? 0 : struct.getLength();
		if (packing != struct.getStoredPackingValue() ||
			minimumAlignment != struct.getStoredMinimumAlignment() ||
			(packing == NO_PACKING && structLength != otherLength)) {
			return false;
		}

		int myNumComps = components.size();
		int otherNumComps = struct.getNumDefinedComponents();
		if (myNumComps != otherNumComps) {
			return false;
		}
		DataTypeComponent[] otherDefinedComponents = struct.getDefinedComponents();
		if (otherDefinedComponents.length != myNumComps) { // safety check
			return false;
		}
		for (int i = 0; i < myNumComps; i++) {
			DataTypeComponent myDtc = components.get(i);
			DataTypeComponent otherDtc = otherDefinedComponents[i];
			if (!myDtc.isEquivalent(otherDtc)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		if (isPackingEnabled()) {
			repack(true);
			return;
		}
		int oldLength = structLength;
		boolean changed = false;
		int n = components.size();
		for (int i = 0; i < n; i++) {
			DataTypeComponentImpl dtc = components.get(i);
			if (dtc.getDataType() == dt) {
				// assume no impact to bitfields since base types
				// should not change size
				int dtcLen = dtc.getLength();
				int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
				if (length < 0) {
					length = dtcLen;
				}
				if (length < dtcLen) {
					dtc.setLength(length);
					shiftOffsets(i + 1, dtcLen - length, 0);
					changed = true;
				}
				else if (length > dtcLen) {
					int consumed = consumeBytesAfter(i, length - dtcLen);
					if (consumed > 0) {
						shiftOffsets(i + 1, 0 - consumed, 0);
						changed = true;
					}
				}
			}
		}
		if (changed) {
			repack(false);
			if (oldLength != structLength) {
				notifySizeChanged();
			}
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (isPackingEnabled()) {
			repack(true);
		}
	}

	/**
	 * 
	 * @param definedComponentIndex the index of the defined component that is consuming the bytes.
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
	 * <p>
	 * WARNING! copying non-packed structures which contain bitfields can produce invalid results when
	 * switching endianess due to the differences in packing order.
	 * 
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public DataType copy(DataTypeManager dtm) {
		StructureDataType struct =
			new StructureDataType(categoryPath, getName(), structLength, dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
	}

	/**
	 * Create cloned structure for target dtm preserving source archive information. WARNING!
	 * cloning non-packed structures which contain bitfields can produce invalid results when
	 * switching endianess due to the differences in packing order.
	 * 
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public StructureDataType clone(DataTypeManager dtm) {
		if (dataMgr == dtm) {
			return this;
		}
		StructureDataType struct =
			new StructureDataType(categoryPath, getName(), structLength, getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;

	}

	@Override
	public void clearComponent(int ordinal) {
		if (isPackingEnabled()) {
			delete(ordinal);
			return;
		}
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
			OrdinalComparator.INSTANCE);
		if (idx >= 0) {
			DataTypeComponent dtc = components.remove(idx);
			dtc.getDataType().removeParent(this);
			int len = dtc.getLength();
			if (len > 1) {
				shiftOffsets(idx, len - 1, 0);
			}
			repack(false);
		}
	}

	/**
	 * Replaces the internal components of this structure with components of the given structure
	 * including packing and alignment settings.
	 * 
	 * @param dataType the structure to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types are not allowed to
	 *             replace a component in this composite data type. For example, suppose dt1
	 *             contains dt2. Therefore it is not valid to replace a dt2 component with dt1 since
	 *             this would cause a cyclic dependency.
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof StructureInternal)) {
			throw new IllegalArgumentException();
		}

		StructureInternal struct = (StructureInternal) dataType;

		components.clear();
		numComponents = 0;
		structLength = 0;
		structAlignment = -1;

		this.packing = struct.getStoredPackingValue();
		this.minimumAlignment = struct.getStoredMinimumAlignment();

		if (struct.isPackingEnabled()) {
			doReplaceWithPacked(struct);
		}
		else {
			doReplaceWithNonPacked(struct);
		}

		repack(false);
		notifySizeChanged();
	}

// TODO: Rename
	private void doReplaceWithPacked(Structure struct) {
		// assumes components is clear and that alignment characteristics have been set
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (DataTypeComponent dtc : otherComponents) {
			DataType dt = dtc.getDataType();
			int length = (dt instanceof Dynamic) ? dtc.getLength() : -1;
			doAdd(dt, length, dtc.getFieldName(), dtc.getComment(), false);
		}
	}

// TODO: Rename
	private void doReplaceWithNonPacked(Structure struct) throws IllegalArgumentException {
		// assumes components is clear and that alignment characteristics have been set.
		if (struct.isNotYetDefined()) {
			return;
		}

		structLength = struct.isZeroLength() ? 0 : struct.getLength();
		numComponents = structLength;

		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			DataType dt = dtc.getDataType().clone(dataMgr);
			checkAncestry(dt);

			int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
			if (length < 0 || dtc.isBitFieldComponent()) {
				// TODO: bitfield truncation/expansion may be an issues if data organization changes
				length = dtc.getLength();
			}
			else {
				// do not exceed available space
				int maxOffset;
				int nextIndex = i + 1;
				if (nextIndex < otherComponents.length) {
					maxOffset = otherComponents[nextIndex].getOffset();
				}
				else {
					maxOffset = structLength;
				}
				if (length > 0) {
					length = Math.min(length, maxOffset - dtc.getOffset());
				}
			}

			components.add(new DataTypeComponentImpl(dt, this, length, dtc.getOrdinal(),
				dtc.getOffset(), dtc.getFieldName(), dtc.getComment()));
		}
		repack(false);
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		boolean changed = false;
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
// FIXME: Consider replacing with undefined type instead of removing (don't remove bitfield)
				components.remove(i);
				shiftOffsets(i, dtc.getLength() - 1, 0);
				--numComponents; // may be revised by repack
				changed = true;
			}
		}
		if (changed) {
			repack(true);
		}
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType replacementDt)
			throws IllegalArgumentException {
		DataType newDt = replacementDt;
		try {
			validateDataType(replacementDt);
			replacementDt = replacementDt.clone(dataMgr);
			checkAncestry(replacementDt);
		}
		catch (Exception e) {
			// TODO: should we use Undefined1 instead to avoid cases where
			// DEFAULT datatype can not be used (bitfield, aligned structure, etc.)
			// TODO: failing silently is rather hidden
			replacementDt = DataType.DEFAULT;
		}

		boolean changed = false;
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
				if (replacementDt == DEFAULT && isPackingEnabled()) {
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
			repack(false);
			notifySizeChanged(); // also handles alignment change
		}
	}

	private void setComponentDataType(DataTypeComponentImpl comp, DataType newDt, int nextIndex) {

		int oldLen = comp.getLength();
		int len = DataTypeComponent.usesZeroLengthComponent(newDt) ? 0 : newDt.getLength();
		if (len < 0) {
			len = oldLen;
		}

		comp.getDataType().removeParent(this);
		comp.setDataType(newDt);
		newDt.addParent(this);

		if (isPackingEnabled()) {
			comp.setLength(len);
			return;
		}

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
			else if (comp.getOrdinal() == getLastDefinedComponentOrdinal()) {
				// we are the last defined component, grow structure
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
	public final DataTypeComponent replace(int index, DataType dataType, int length) {
		return replace(index, dataType, length, null, null);
	}
	
	@Override
	public DataTypeComponent replace(int ordinal, DataType dataType, int length, String componentName,
			String comment) throws IndexOutOfBoundsException, IllegalArgumentException {
		if (ordinal < 0 || ordinal >= numComponents) {
			throw new IndexOutOfBoundsException(ordinal);
		}

		dataType = validateDataType(dataType);

		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		length = getPreferredComponentLength(dataType, length);

		LinkedList<DataTypeComponentImpl> replacedComponents = new LinkedList<>();
		int offset;

		int index = ordinal;
		if (!isPackingEnabled()) {
			index = Collections.binarySearch(components, Integer.valueOf(ordinal),
				OrdinalComparator.INSTANCE);
		}
		if (index >= 0) {
			// defined component
			DataTypeComponentImpl origDtc = components.get(index);
			offset = origDtc.getOffset();
			
			if (isPackingEnabled() || length == 0) {
				// case 1: packed structure or zero-length replacement - do 1-for-1 replacement
				replacedComponents.add(origDtc);
			}
			else if (origDtc.getLength() == 0) {
				// case 2: replaced component is zero-length (like-for-like replacement handled by case 1 above
				throw new IllegalArgumentException(
					"Zero-length component may only be replaced with another zero-length component");
			}
			else if (origDtc.isBitFieldComponent()) {
				// case 3: replacing bit-field (must replace all bit-fields which overlap)
				int minOffset = origDtc.getOffset();
				int maxOffset = origDtc.getEndOffset();

				replacedComponents.add(origDtc);

				// consume bit-field overlaps before
				for (int i = index - 1; i >= 0; i--) {
					origDtc = components.get(i);
					if (origDtc.getLength() == 0 || !origDtc.containsOffset(minOffset)) {
						break;
					}
					replacedComponents.add(0, origDtc);
				}

				// consume bit-field overlaps after
				for (int i = index + 1; i < components.size(); i++) {
					origDtc = components.get(i);
					if (origDtc.getLength() == 0 || !origDtc.containsOffset(maxOffset)) {
						break;
					}
					replacedComponents.add(origDtc);
				}
			}
			else {
				// case 4: sized component replacemnt - do 1-for-1 replacement 
				replacedComponents.add(origDtc);
			}
		}
		else {
			// case 5: undefined component replaced (non-packed only)
			index = -index - 1;
			offset = ordinal;
			if (index > 0) {
				// use previous defined component to compute undefined offset
				DataTypeComponent dtc = components.get(index - 1);
				offset = dtc.getEndOffset() + ordinal - dtc.getOrdinal();
				if (dtc.getLength() == 0) {
					--offset;
				}
			}
			DataTypeComponentImpl origDtc =
				new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
			if (dataType == DataType.DEFAULT) {
				return origDtc; // no change
			}
			replacedComponents.add(origDtc);
		}

		DataTypeComponent replaceComponent =
			replaceComponents(replacedComponents, dataType, offset, length, componentName, comment);

		repack(false);
		notifySizeChanged();

		return replaceComponent != null ? replaceComponent : getComponent(ordinal);
	}

	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length,
			String name, String comment) throws IllegalArgumentException {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset >= structLength) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is beyond end of structure (" + structLength + ").");
		}

		dataType = validateDataType(dataType);
		dataType = dataType.clone(dataMgr);
		checkAncestry(dataType);

		LinkedList<DataTypeComponentImpl> replacedComponents = new LinkedList<>();

		DataTypeComponentImpl origDtc = null;
		int index = Collections.binarySearch(components, Integer.valueOf(offset),
			OffsetComparator.INSTANCE);
		if (index >= 0) {

			// defined component found - advance to last one containing offset
			index = advanceToLastComponentContainingOffset(index, offset);
			origDtc = components.get(index);

			// case 1: only defined component(s) at offset are zero-length
			if (origDtc.getLength() == 0) {
				if (isPackingEnabled()) {
					// if packed: insert after zero-length component 
					return insert(index + 1, dataType, length, name, comment);
				}
				// if non-packed: replace undefined component which immediately follows the zero-length component
				replacedComponents.add(new DataTypeComponentImpl(DataType.DEFAULT, this, 1,
					origDtc.getOrdinal() + 1, offset));
			}

			// case 2: sized component at offset is bit-field (must replace all bit-fields which contain offset)
			else if (origDtc.isBitFieldComponent()) {
				replacedComponents.add(origDtc);
				for (int i = index - 1; i >= 0; i--) {
					origDtc = components.get(i);
					if (origDtc.getLength() == 0 || !origDtc.containsOffset(offset)) {
						break;
					}
					replacedComponents.add(0, origDtc);
				}
			}

			// case 3: normal replacement of sized component
			else {
				replacedComponents.add(origDtc);
			}
		}
		else {
			// defined component not found
			index = -index - 1;

			if (isPackingEnabled()) {
				// case 4: if replacing padding for packed struction perform insert at correct ordinal
				return insert(index, dataType, length, name, comment);
			}

			// case 5: replace undefined component at offset - compute undefined component to be replaced
			int ordinal = offset;
			if (index > 0) {
				// use previous defined component to determine ordinal for undefined component
				DataTypeComponent dtc = components.get(index - 1);
				ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
			}
			origDtc = new DataTypeComponentImpl(DataType.DEFAULT, this, 1, ordinal, offset);
			if (dataType == DataType.DEFAULT) {
				return origDtc; // no change
			}
			replacedComponents.add(origDtc);
		}

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponent replaceComponent =
			replaceComponents(replacedComponents, dataType, offset, length, name, comment);

		repack(false);
		notifySizeChanged();

		return replaceComponent != null ? replaceComponent : getComponentContaining(offset);
	}

	/**
	 * Check for available undefined bytes within a non-packed structure for a component
	 * update with the specified ordinal.  
	 * @param lastOrdinalReplacedOrUpdated the ordinal of a component to be updated
	 * or the last ordinal with in a sequence of components being replaced.
	 * @param bytesNeeded number of additional bytes required to complete operation
	 * @throws IllegalArgumentException if unable to identify/make sufficient space
	 */
	private void checkUndefinedSpaceAvailabilityAfter(int lastOrdinalReplacedOrUpdated,
			int bytesNeeded, DataType newDataType, int offset) throws IllegalArgumentException {
		if (bytesNeeded <= 0) {
			return;
		}
		int bytesAvailable = getNumUndefinedBytes(lastOrdinalReplacedOrUpdated + 1);
		if (bytesAvailable < bytesNeeded) {
			if (lastOrdinalReplacedOrUpdated == getLastDefinedComponentOrdinal()) {
				growStructure(bytesNeeded - bytesAvailable);
			}
			else {
				throw new IllegalArgumentException("Not enough undefined bytes to fit " +
					newDataType.getPathName() + " in structure " + getPathName() + " at offset 0x" +
					Integer.toHexString(offset) + "." + " It needs " +
					(bytesNeeded - bytesAvailable) + " more byte(s) to be able to fit.");
			}
		}
	}

	/**
	 * Replace the specified components with a new component containing the specified data type.
	 * If {@link DataType#DEFAULT} is specified as the resolvedDataType only a clear operation 
	 * is performed.
	 * 
	 * @param origComponents the original sequence of data type components in this structure 
	 *        to be replaced.  These components must be adjacent components in sequential order.
	 *        If an non-packed undefined component is specified no other component may be included.
	 * @param dataType the data type of the new component
	 * @param newOffset offset of replacement component which must fall within origComponents bounds
	 * @param length the length of the new component
	 * @param name the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if only a clear operation was performed.
	 * @throws IllegalArgumentException if unable to identify/make sufficient space 
	 */
	private DataTypeComponent replaceComponents(LinkedList<DataTypeComponentImpl> origComponents,
			DataType dataType, int newOffset, int length, String name, String comment)
			throws IllegalArgumentException {

		boolean clearOnly = false;
		if (dataType == DataType.DEFAULT) {
			clearOnly = true;
			length = 0; // nothing gets consumed
		}

		DataTypeComponentImpl origFirstDtc = origComponents.getFirst();
		DataTypeComponentImpl origLastDtc = origComponents.getLast();
		int origFirstOrdinal = origFirstDtc.getOrdinal();
		int origLastOrdinal = origLastDtc.getOrdinal();
		int minReplacedOffset = origFirstDtc.getOffset();
		int maxReplacedOffset = origLastDtc.getEndOffset();

		// Perform origComponents checks
		if (newOffset < minReplacedOffset || newOffset > maxReplacedOffset) {
			throw new AssertException("newOffset not contained within origComponents");
		}
		if (origComponents.size() > 1) {
			int checkOrdinal = origFirstOrdinal;
			for (DataTypeComponentImpl origDtc : origComponents) {
				if (origDtc.isUndefined()) {
					throw new AssertException(
						"undefined component within multi-component sequence");
				}
				if (origDtc.getOrdinal() != checkOrdinal++) {
					throw new AssertException("non-sequential components specified");
				}
			}
		}

		int leadingUnusedBytes = newOffset - minReplacedOffset;
		int newOrdinal = origFirstOrdinal;
		if (!isPackingEnabled()) {
			newOrdinal += leadingUnusedBytes; // leading unused bytes will become undefined components
		}

		// compute space freed by component removal
		int origLength = 0;
		if (origLastDtc.getLength() != 0) {
			origLength = maxReplacedOffset - minReplacedOffset + 1;
		}

		if (!clearOnly && !isPackingEnabled()) {
			int bytesNeeded = length - origLength + leadingUnusedBytes;
			checkUndefinedSpaceAvailabilityAfter(origLastOrdinal, bytesNeeded, dataType,
				newOffset);
		}

		// determine defined component list insertion point, remove old components
		// and insert new component in list
		int index;
		if (isPackingEnabled()) {
			index = newOrdinal;
		}
		else {
			index = Collections.binarySearch(components, Integer.valueOf(origFirstOrdinal),
				OrdinalComparator.INSTANCE);
		}
		if (index < 0) {
			index = -index - 1; // undefined component replacement
		}
		else {
			for (DataTypeComponentImpl origDtc : origComponents) {
				DataTypeComponentImpl dtc = doDelete(index);
				if (dtc != origDtc) {
					throw new AssertException("component replacement mismatch");
				}
			}
		}

		DataTypeComponentImpl newDtc = null;
		if (!clearOnly) {
			// insert new component
			newDtc = new DataTypeComponentImpl(dataType, this, length, newOrdinal,
				newOffset, name, comment);
			components.add(index, newDtc);
		}

		// adjust ordinals of trailing components - defer if packing is enabled
		if (!isPackingEnabled()) {
			int deltaOrdinal = -origComponents.size() + origLength - length;
			shiftOffsets(index + 1, deltaOrdinal, 0);
		}
		return newDtc;
	}

	private int getLastDefinedComponentOrdinal() {
		if (components.size() == 0) {
			return 0;
		}
		DataTypeComponent dataTypeComponent = components.get(components.size() - 1);
		return dataTypeComponent.getOrdinal();
	}

	/**
	 * Gets the number of Undefined bytes beginning at the indicated component index. Undefined
	 * bytes that have a field name or comment specified are also included.
	 * 
	 * @param index the component index to begin checking at.
	 * @return the number of contiguous undefined bytes
	 */
	protected int getNumUndefinedBytes(int index) {
		if (index >= numComponents) {
			return 0;
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(index),
			OrdinalComparator.INSTANCE);
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
	public boolean dependsOn(DataType dt) {
		return false;
	}

	@Override
	public void deleteAll() {
		for (DataTypeComponentImpl dtc : components) {
			dtc.getDataType().removeParent(this);
		}
		components.clear();
		structLength = 0;
		numComponents = 0;
		notifySizeChanged();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public boolean repack(boolean notify) {

		int oldLength = structLength;
		int oldAlignment = getAlignment();

		boolean changed;
		if (!isPackingEnabled()) {
			changed = adjustNonPackedComponents();
		}
		else {
			StructurePackResult packResult =
				AlignedStructurePacker.packComponents(this, components);
			changed = packResult.componentsChanged;
			changed |= (structLength != packResult.structureLength) ||
				(structAlignment != packResult.alignment) ||
					(numComponents != packResult.numComponents);
			structLength = packResult.structureLength;
			structAlignment = packResult.alignment;
			numComponents = components.size();
		}

		if (changed && notify) {
			if (oldLength != structLength) {
				notifySizeChanged();
			}
			else if (oldAlignment != structAlignment) {
				notifyAlignmentChanged();
			}
		}
		return changed;
	}

	private boolean adjustNonPackedComponents() {
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
		if (numComponents != componentCount) {
			numComponents = componentCount;
			changed = true;
		}
		int alignment = getNonPackedAlignment();
		if (alignment != structAlignment) {
			structAlignment = alignment;
			changed = true;
		}
		return changed;
	}

	private void doGrowStructure(int amount) {
		if (isPackingEnabled()) {
			throw new AssertException("only valid for non-packed");
		}
		numComponents += amount;
		structLength += amount;
	}

}
