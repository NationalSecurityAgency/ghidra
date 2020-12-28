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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;

import db.Field;
import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.data.AlignedStructurePacker.StructurePackResult;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * Structure implementation for the Database.
 *
 *
 */
class StructureDB extends CompositeDB implements Structure {
	private static OrdinalComparator ordinalComparator = new OrdinalComparator();
	private static OffsetComparator offsetComparator = new OffsetComparator();
	private static ComponentComparator componentComparator = new ComponentComparator();
	protected static Comparator<Object> bitOffsetComparatorLE = new BitOffsetComparator(false);
	protected static Comparator<Object> bitOffsetComparatorBE = new BitOffsetComparator(true);
	private int structLength;
	private int numComponents; // If aligned, this does not include the undefined data types.
	private ArrayList<DataTypeComponentDB> components;
	private DataTypeComponentDB flexibleArrayComponent;
	private int alignment = -1;

	/**
	 * Constructor
	 * 
	 * @param dataMgr
	 * @param cache
	 * @param compositeAdapter
	 * @param componentAdapter
	 * @param record
	 */
	public StructureDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			CompositeDBAdapter compositeAdapter, ComponentDBAdapter componentAdapter,
			DBRecord record) {
		super(dataMgr, cache, compositeAdapter, componentAdapter, record);
	}

	@Override
	protected void initialize() {

		components = new ArrayList<>();

		try {
			Field[] ids = componentAdapter.getComponentIdsInComposite(key);
			for (Field id : ids) {
				DBRecord rec = componentAdapter.getRecord(id.getLongValue());
				DataTypeComponentDB component =
					new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
				if (component.isFlexibleArrayComponent()) {
					flexibleArrayComponent = component;
				}
				else {
					components.add(component);
				}
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}

		Collections.sort(components, componentComparator);

		structLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);
		numComponents = record.getIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL);
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Structure>";
		}
		return "";
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String name, String comment)
			throws IllegalArgumentException {
		try {
			return doAdd(dataType, length, name, comment, true);
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	private DataTypeComponent doAdd(DataType dataType, int length, String name, String comment,
			boolean validateAlignAndNotify)
			throws DataTypeDependencyException, IllegalArgumentException {
		lock.acquire();
		try {
			checkDeleted();

			if (validateAlignAndNotify) {
				validateDataType(dataType);
				dataType = resolve(dataType);
				checkAncestry(dataType);
			}

			DataTypeComponentDB dtc = null;
			try {
				if (dataType == DataType.DEFAULT) {
					dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, key,
						numComponents, structLength);
				}
				else {
					int componentLength = getPreferredComponentLength(dataType, length);
					DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key,
						componentLength, numComponents, structLength, name, comment);
					dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
					dataType.addParent(this);
					components.add(dtc);
				}

				int structureGrowth = dtc.getLength();
				if (!isInternallyAligned() && length > 0) {
					structureGrowth = length;
				}

				++numComponents;
				structLength += structureGrowth;

				if (validateAlignAndNotify) {

					record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL,
						numComponents);
					record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
					compositeAdapter.updateRecord(record, true);

					adjustInternalAlignment(false);
					notifySizeChanged();
				}
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
			return dtc;
		}
		finally {
			lock.release();
		}
	}

	private DataTypeComponent doAddFlexArray(DataType dataType, String name, String comment,
			boolean validateAlignAndNotify)
			throws DataTypeDependencyException, IllegalArgumentException {
		lock.acquire();
		try {
			checkDeleted();

			if (validateAlignAndNotify) {
				validateDataType(dataType);
				dataType = resolve(dataType);
				if (isInvalidFlexArrayDataType(dataType)) {
					throw new IllegalArgumentException(
						"Unsupported flexType: " + dataType.getDisplayName());
				}
				checkAncestry(dataType);
			}

			DataTypeComponentDB dtc = null;
			try {

				int oldLength = structLength;

				if (flexibleArrayComponent != null) {
					flexibleArrayComponent.getDataType().removeParent(this);
					componentAdapter.removeRecord(flexibleArrayComponent.getKey());
					flexibleArrayComponent = null;
				}

				DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, 0,
					-1, -1, name, comment);
				dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
				dataType.addParent(this);
				flexibleArrayComponent = dtc;

				if (validateAlignAndNotify) {
					adjustInternalAlignment(false);
					if (oldLength != structLength) {
						notifySizeChanged();
					}
					else {
						dataMgr.dataTypeChanged(this);
					}
				}
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
			return dtc;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void growStructure(int amount) {
		lock.acquire();
		try {
			checkDeleted();
			if (!isInternallyAligned()) {
				doGrowStructure(amount);
			}
			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	private void doGrowStructure(int amount) {
		if (!isInternallyAligned()) {
			numComponents += amount;
		}
		record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
		structLength += amount;
		record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
		try {
			compositeAdapter.updateRecord(record, true);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) {
		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal > numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			if (ordinal == numComponents) {
				return add(dataType, length, name, comment);
			}
			validateDataType(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

			int idx;
			if (isInternallyAligned()) {
				idx = ordinal;
			}
			else {
				// TODO: could improve insertion of bitfield which does not intersect
				// existing ordinal bitfield at the bit-level
				idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
					ordinalComparator);
				if (idx > 0) {
					DataTypeComponentDB existingDtc = components.get(idx);
					if (existingDtc.isBitFieldComponent()) {
						// must shift down to eliminate possible overlap with previous component
						DataTypeComponentDB previousDtc = components.get(idx - 1);
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
				notifySizeChanged();
				return getComponent(ordinal);
			}

			length = getPreferredComponentLength(dataType, length);

			int offset = getComponent(ordinal).getOffset();
			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, length,
				ordinal, offset, name, comment);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			dataType.addParent(this);
			shiftOffsets(idx, 1, dtc.getLength());
			components.add(idx, dtc);
			adjustInternalAlignment(true);
			notifySizeChanged();
			return dtc;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) throws InvalidDataTypeException {

		BitFieldDataType.checkBaseDataType(baseDataType);
		baseDataType = baseDataType.clone(getDataTypeManager());

		BitFieldDataType bitFieldDt = new BitFieldDBDataType(baseDataType, bitSize, 0);
		return add(bitFieldDt, componentName, comment);
	}

	@Override
	public DataTypeComponent insertBitField(int ordinal, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException, ArrayIndexOutOfBoundsException {

		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal > numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}

			if (!isInternallyAligned()) {
				int offset = structLength;
				if (ordinal < numComponents) {
					offset = getComponent(ordinal).getOffset();
				}
				return insertBitFieldAt(offset, byteWidth, bitOffset, baseDataType, bitSize,
					componentName, comment);
			}

			// handle aligned bitfield insertion
			BitFieldDataType bitFieldDt = new BitFieldDBDataType(baseDataType, bitSize, 0);
			return insert(ordinal, bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
			DataType baseDataType, int bitSize, String componentName, String comment)
			throws InvalidDataTypeException {
		lock.acquire();
		try {
			checkDeleted();
			BitFieldDataType.checkBaseDataType(baseDataType);
			baseDataType = baseDataType.clone(dataMgr);

			if (byteOffset < 0 || bitSize < 0) {
				throw new IllegalArgumentException(
					"Negative values not permitted when defining bitfield");
			}
			if (byteWidth <= 0) {
				throw new IllegalArgumentException("Invalid byteWidth");
			}

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

			int startBitOffset = BitOffsetComparator.getNormalizedBitfieldOffset(byteOffset,
				byteWidth, effectiveBitSize, bitOffset, bigEndian);

			Comparator<Object> bitOffsetComparator =
				bigEndian ? bitOffsetComparatorBE : bitOffsetComparatorLE;
			int startIndex = Collections.binarySearch(components, Integer.valueOf(startBitOffset),
				bitOffsetComparator);
			if (startIndex < 0) {
				startIndex = -startIndex - 1;
			}
			else {
				hasConflict = true;
				DataTypeComponentDB dtc = components.get(startIndex);
				if (bitSize == 0 || dtc.isZeroBitFieldComponent()) {
					hasConflict = dtc.getOffset() != (startBitOffset / 8);
				}
				if (hasConflict) {
					additionalShift = byteOffset - dtc.getOffset();
				}
			}

			int ordinal; // computed ordinal will be adjusted after insertion complete
			if (startIndex < components.size()) {
				DataTypeComponentDB dtc = components.get(startIndex);
				ordinal = dtc.getOrdinal();
			}
			else {
				ordinal = startIndex;
			}

			if (isInternallyAligned()) {
				insertBitField(ordinal, 0, 0, baseDataType, effectiveBitSize, componentName,
					comment);
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

			BitFieldDataType bitfieldDt =
				new BitFieldDBDataType(baseDataType, bitSize, storageBitOffset);

			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(bitfieldDt), key,
				bitfieldDt.getStorageSize(), ordinal, revisedOffset, componentName, comment);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			bitfieldDt.addParent(this); // has no affect
			components.add(startIndex, dtc);

			adjustUnalignedComponents();
			notifySizeChanged();
			return dtc;
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public void delete(int ordinal) {
		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
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
				adjustInternalAlignment(false);
			}
			else {
				// assume unaligned removal of DEFAULT
				idx = -idx - 1;
				shiftOffsets(idx, -1, -1);
			}
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	private void doDelete(int index) {
		DataTypeComponentDB dtc = components.remove(index);
		dtc.getDataType().removeParent(this);
		try {
			componentAdapter.removeRecord(dtc.getKey());
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		if (isInternallyAligned()) {
			return;
		}
		int shiftAmount = dtc.isBitFieldComponent() ? 0 : dtc.getLength();
		shiftOffsets(index, -1, -shiftAmount);
	}

	@Override
	public void delete(int[] ordinals) {
		lock.acquire();
		try {
			checkDeleted();
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
			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isPartOf(DataType dataType) {
		lock.acquire();
		try {
			checkIsValid();
			if (equals(dataType)) {
				return true;
			}
			for (DataTypeComponentDB dtc : components) {
				DataType subDt = dtc.getDataType();
				if (subDt instanceof Composite) {
					if (((Composite) subDt).isPartOf(dataType)) {
						return true;
					}
				}
				else if (subDt.equals(dataType)) {
					return true;
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumComponents() {
		lock.acquire();
		try {
			checkIsValid();
			return numComponents;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumDefinedComponents() {
		lock.acquire();
		try {
			return components.size();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent getComponent(int ordinal) {
		lock.acquire();
		try {
			checkIsValid();
			if (ordinal == numComponents && flexibleArrayComponent != null) {
				return flexibleArrayComponent;
			}
			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			if (isInternallyAligned()) {
				return components.get(ordinal);
			}
			int idx =
				Collections.binarySearch(components, Integer.valueOf(ordinal), ordinalComparator);
			if (idx >= 0) {
				return components.get(idx);
			}
			int offset = 0;
			idx = -idx - 1;
			if (idx == 0) {
				offset = ordinal;
			}
			else {
				DataTypeComponent dtc = components.get(idx - 1);
				offset = dtc.getEndOffset() + ordinal - dtc.getOrdinal();
			}

			return new DataTypeComponentDB(dataMgr, componentAdapter, this, key, ordinal, offset);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent[] getComponents() {
		lock.acquire();
		try {
			checkIsValid();
			DataTypeComponent[] comps = new DataTypeComponent[numComponents];
			for (int i = 0; i < comps.length; i++) {
				comps[i] = getComponent(i);
			}
			return comps;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Create copy of structure for target dtm (source archive information is discarded). 
	 * <p>
	 * WARNING! copying unaligned structures which contain bitfields can produce invalid results when
	 * switching endianess due to the differences in packing order.
	 * 
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public DataType copy(DataTypeManager dtm) {
		StructureDataType struct =
			new StructureDataType(getCategoryPath(), getName(), getLength(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
	}

	/**
	 * Create cloned structure for target dtm preserving source archive information. WARNING!
	 * cloning unaligned structures which contain bitfields can produce invalid results when
	 * switching endianess due to the differences in packing order.
	 * 
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public Structure clone(DataTypeManager dtm) {
		StructureDataType struct =
			new StructureDataType(getCategoryPath(), getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
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
			// just in case - alignment should have been previously determined and stored
			StructurePackResult packResult = AlignedStructureInspector.packComponents(this);
			alignment = packResult.alignment;
		}
		return alignment;
	}

	@Override
	public int getLength() {
		lock.acquire();
		try {
			checkIsValid();
			if (structLength == 0) {
				return 1; // lie about our length if not yet defined
			}
			return structLength;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void clearComponent(int ordinal) {
		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			int idx;
			if (isInternallyAligned()) {
				idx = ordinal;
			}
			else {
				idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
					ordinalComparator);
			}
			if (idx >= 0) {
				DataTypeComponentDB dtc = components.remove(idx);
				dtc.getDataType().removeParent(this);
				try {
					componentAdapter.removeRecord(dtc.getKey());
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
				int len = dtc.getLength();
				if (len > 1) {
					shiftOffsets(idx, len - 1, 0);
				}
				adjustInternalAlignment(true);
				dataMgr.dataTypeChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Backup from specified ordinal to the first component which contains the specified offset. For
	 * normal components the specified ordinal will be returned, however for bit-fields the ordinal
	 * of the first bit-field containing the specified offset will be returned.
	 * 
	 * @param ordinal component ordinal
	 * @param offset offset within structure
	 * @return index of first defined component containing specific offset.
	 */
	private int backupToFirstComponentContainingOffset(int index, int offset) {
		if (index == 0) {
			return 0;
		}
		DataTypeComponentDB dtc = components.get(index);
		while (index != 0 && dtc.isBitFieldComponent()) {
			DataTypeComponentDB previous = components.get(index - 1);
			if (!previous.containsOffset(offset)) {
				break;
			}
			dtc = previous;
			--index;
		}
		return index;
	}

	/**
	 * Advance from specified ordinal to the last component which contains the specified offset. For
	 * normal components the specified ordinal will be returned, however for bit-fields the ordinal
	 * of the last bit-field containing the specified offset will be returned.
	 * 
	 * @param ordinal component ordinal
	 * @param offset offset within structure
	 * @return index of last defined component containing specific offset.
	 */
	private int advanceToLastComponentContainingOffset(int index, int offset) {
		DataTypeComponentDB dtc = components.get(index);
		while (index < (components.size() - 1) && dtc.isBitFieldComponent()) {
			DataTypeComponentDB next = components.get(index + 1);
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
		lock.acquire();
		try {
			checkDeleted();
			if (offset < 0) {
				throw new IllegalArgumentException("Offset cannot be negative.");
			}
			if (offset >= structLength) {
				return;
			}
			int index =
				Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);

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
				DataTypeComponentDB dtc = components.get(index);
				while (dtc.containsOffset(offset)) {
					doDelete(index);
					if (--index < 0) {
						break;
					}
					dtc = components.get(index);
				}
			}

			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent getComponentAt(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset >= structLength || offset < 0) {
				return null;
			}
			int index =
				Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);
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
			return new DataTypeComponentDB(dataMgr, componentAdapter, this, key, ordinal, offset);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		lock.acquire();
		try {
			DataTypeComponent dtc = getComponentAt(offset);
			if (dtc != null) {
				DataType dt = dtc.getDataType();
				if (dt instanceof Structure) {
					return ((Structure) dt).getDataTypeAt(offset - dtc.getOffset());
				}
			}
			return dtc;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponentDB[] getDefinedComponents() {
		lock.acquire();
		try {
			checkIsValid();
			return components.toArray(new DataTypeComponentDB[components.size()]);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public final DataTypeComponent insertAtOffset(int offset, DataType dataType, int length)
			throws IllegalArgumentException {
		return insertAtOffset(offset, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {

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
					bfDt.getDeclaredBitSize(), name, comment);
			}
			catch (InvalidDataTypeException e) {
				throw new AssertException(e);
			}
		}

		lock.acquire();
		try {
			checkDeleted();
			validateDataType(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

			if ((offset > structLength) && !isInternallyAligned()) {
				numComponents = numComponents + (offset - structLength);
				structLength = offset;
			}

			int index =
				Collections.binarySearch(components, Integer.valueOf(offset), offsetComparator);

			int additionalShift = 0;
			if (index >= 0) {
				index = backupToFirstComponentContainingOffset(index, offset);
				DataTypeComponentDB dtc = components.get(index);
				additionalShift = offset - dtc.getOffset();
			}
			else {
				index = -index - 1;
			}

			int ordinal = offset;
			if (index > 0) {
				DataTypeComponentDB dtc = components.get(index - 1);
				ordinal = dtc.getOrdinal() + offset - dtc.getEndOffset();
			}

			if (dataType == DataType.DEFAULT) {
				// assume unaligned insert of DEFAULT
				shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
				adjustInternalAlignment(true);
				notifySizeChanged();
				return new DataTypeComponentDB(dataMgr, componentAdapter, this, key, ordinal,
					offset);
			}

			length = getPreferredComponentLength(dataType, length);

			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, length,
				ordinal, offset, name, comment);
			dataType.addParent(this);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			shiftOffsets(index, 1 + additionalShift, dtc.getLength() + additionalShift);
			components.add(index, dtc);
			adjustInternalAlignment(true);
			notifySizeChanged();
			return dtc;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public DataTypeComponent replace(int ordinal, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {
		lock.acquire();
		try {
			checkDeleted();

			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}

			validateDataType(dataType);

			DataTypeComponent origDtc = getComponent(ordinal);
			if (origDtc.isBitFieldComponent()) {
				throw new IllegalArgumentException(
					"Bit-field component may not be directly replaced");
			}

			if (dataType == DataType.DEFAULT) {
				clearComponent(ordinal);
				return getComponent(ordinal);
			}

			dataType = resolve(dataType);
			checkAncestry(dataType);

			length = getPreferredComponentLength(dataType, length);

			DataTypeComponent replaceComponent =
				replaceComponent(origDtc, dataType, length, name, comment, true);
			adjustInternalAlignment(true);
			return replaceComponent;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public final DataTypeComponent replace(int ordinal, DataType dataType, int length)
			throws IllegalArgumentException {
		return replace(ordinal, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		if (offset >= getLength()) {
			throw new IllegalArgumentException(
				"Offset " + offset + " is beyond end of structure (" + structLength + ").");
		}

		lock.acquire();
		try {
			checkDeleted();

			validateDataType(dataType);

			DataTypeComponent origDtc = getComponentAt(offset);
			if (origDtc.isBitFieldComponent()) {
				throw new IllegalArgumentException(
					"Bit-field component may not be directly replaced");
			}

			if (dataType == DataType.DEFAULT) {
				int ordinal = origDtc.getOrdinal();
				clearComponent(ordinal);
				return getComponent(ordinal);
			}

			dataType = resolve(dataType);
			checkAncestry(dataType);

			length = getPreferredComponentLength(dataType, length);

			DataTypeComponent replaceComponent =
				replaceComponent(origDtc, dataType, length, name, comment, true);

			adjustInternalAlignment(true);
			return replaceComponent;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Replaces the internal components of this structure with components of the given structure.
	 * 
	 * @param dataType the structure to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types are not allowed to
	 *             replace a component in this composite data type. For example, suppose dt1
	 *             contains dt2. Therefore it is not valid to replace a dt2 component with dt1 since
	 *             this would cause a cyclic dependency.
	 * @see ghidra.program.database.data.DataTypeDB#replaceWith(ghidra.program.model.data.DataType)
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException();
		}
		lock.acquire();
		boolean isResolveCacheOwner = dataMgr.activateResolveCache();
		try {
			checkDeleted();
			doReplaceWith((Structure) dataType, true);
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			if (isResolveCacheOwner) {
				dataMgr.flushResolveQueue(true);
			}
			lock.release();
		}
	}

	/**
	 * Perform component replacement.
	 * 
	 * @param struct
	 * @param notify
	 * @return true if fully completed else false if pointer component post resolve required
	 * @throws DataTypeDependencyException
	 * @throws IOException
	 */
	void doReplaceWith(Structure struct, boolean notify)
			throws DataTypeDependencyException, IOException {

		// pre-resolved component types to catch dependency issues early
		DataTypeComponent flexComponent = struct.getFlexibleArrayComponent();
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		DataType[] resolvedDts = new DataType[otherComponents.length];
		for (int i = 0; i < otherComponents.length; i++) {
			resolvedDts[i] = doCheckedResolve(otherComponents[i].getDataType());
		}
		DataType resolvedFlexDt = null;
		if (flexComponent != null) {
			resolvedFlexDt = doCheckedResolve(flexComponent.getDataType());
			if (isInvalidFlexArrayDataType(resolvedFlexDt)) {
				throw new IllegalArgumentException(
					"Unsupported flexType: " + resolvedFlexDt.getDisplayName());
			}
		}

		int oldLength = structLength;
		int oldMinAlignment = getMinimumAlignment();

		for (DataTypeComponentDB dtc : components) {
			dtc.getDataType().removeParent(this);
			componentAdapter.removeRecord(dtc.getKey());
		}
		components.clear();
		numComponents = 0;
		structLength = 0;

		if (flexibleArrayComponent != null) {
			flexibleArrayComponent.getDataType().removeParent(this);
			componentAdapter.removeRecord(flexibleArrayComponent.getKey());
			flexibleArrayComponent = null;
		}

		setAlignment(struct, false);

		if (struct.isInternallyAligned()) {
			doReplaceWithAligned(struct, resolvedDts);
		}
		else {
			doReplaceWithUnaligned(struct, resolvedDts);
		}

		if (flexComponent != null) {
			doAddFlexArray(resolvedFlexDt, flexComponent.getFieldName(), flexComponent.getComment(),
				false);
		}

		record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
		record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);

		compositeAdapter.updateRecord(record, false);

		adjustInternalAlignment(false);

		if (notify) {
			if (oldMinAlignment != getMinimumAlignment()) {
				notifyAlignmentChanged();
			}
			else if (oldLength != structLength) {
				notifySizeChanged();
			}
			else {
				dataMgr.dataTypeChanged(this);
			}
		}

		if (pointerPostResolveRequired) {
			dataMgr.queuePostResolve(this, struct);
		}
	}

	private void doReplaceWithAligned(Structure struct, DataType[] resolvedDts) {
		// assumes components is clear and that alignment characteristics have been set
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			DataType dt = dtc.getDataType();
			int length = (dt instanceof Dynamic) ? dtc.getLength() : -1;
			try {
				doAdd(resolvedDts[i], length, dtc.getFieldName(), dtc.getComment(), false);
			}
			catch (DataTypeDependencyException e) {
				throw new AssertException(e); // ancestry check already performed by caller
			}
		}
	}

	private void doReplaceWithUnaligned(Structure struct, DataType[] resolvedDts)
			throws IOException {
		// assumes components is clear and that alignment characteristics have been set.
		if (struct.isNotYetDefined()) {
			return;
		}

		structLength = struct.getLength();
		numComponents = structLength;

		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];

			DataType dt = resolvedDts[i]; // ancestry check already performed by caller

			int length = dt.getLength();
			if (length <= 0 || dtc.isBitFieldComponent()) {
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
					maxOffset = struct.getLength();
				}
				length = Math.min(length, maxOffset - dtc.getOffset());
			}

			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dt), key, length,
				dtc.getOrdinal(), dtc.getOffset(), dtc.getFieldName(), dtc.getComment());
			dt.addParent(this);
			DataTypeComponentDB newDtc =
				new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			components.add(newDtc);
		}
		adjustComponents(false);
	}

	@Override
	protected void postPointerResolve(DataType definitionDt, DataTypeConflictHandler handler) {

		Structure struct = (Structure) definitionDt;
		if (struct.hasFlexibleArrayComponent() != hasFlexibleArrayComponent()) {
			throw new IllegalArgumentException("mismatched definition datatype");
		}

		super.postPointerResolve(definitionDt, handler);

		if (flexibleArrayComponent != null) {
			DataTypeComponent flexDtc = struct.getFlexibleArrayComponent();
			DataType dt = flexDtc.getDataType();
			if (dt instanceof Pointer) {
				flexibleArrayComponent.getDataType().removeParent(this);
				dt = dataMgr.resolve(dt, handler);
				flexibleArrayComponent.setDataType(dt);
				dt.addParent(this);
			}
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			boolean didChange = false;
			if (flexibleArrayComponent != null && flexibleArrayComponent.getDataType() == dt) {
				flexibleArrayComponent.getDataType().removeParent(this);
				componentAdapter.removeRecord(flexibleArrayComponent.getKey());
				flexibleArrayComponent = null;
				didChange = true;
			}
			int n = components.size();
			for (int i = n - 1; i >= 0; i--) {
				DataTypeComponentDB dtc = components.get(i);
				boolean removeBitFieldComponent = false;
				if (dtc.isBitFieldComponent()) {
					BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
					removeBitFieldComponent = bitfieldDt.getBaseDataType() == dt;
				}
				if (removeBitFieldComponent || dtc.getDataType() == dt) {
					dt.removeParent(this);
					components.remove(i);
					shiftOffsets(i, dtc.getLength() - 1, 0); // ordinals only
					componentAdapter.removeRecord(dtc.getKey());
					didChange = true;
				}
			}
			if (didChange) {
				adjustInternalAlignment(true);
				notifySizeChanged();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		lock.acquire();
		try {
			checkDeleted();
			if (isInternallyAligned()) {
				adjustComponents(true); // notifies parents
				return;
			}
			boolean didChange = false;
			boolean warn = false;
			int n = components.size();
			for (int i = 0; i < n; i++) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.getDataType() == dt) {
					// assume no impact to bitfields since base types
					// should not change size
					int dtcLen = dtc.getLength();
					int length = dt.getLength();
					if (length <= 0) {
						length = dtcLen;
					}
					if (length < dtcLen) {
						dtc.setLength(length, true);
						shiftOffsets(i + 1, dtcLen - length, 0);
						didChange = true;
					}
					else if (length > dtcLen) {
						int consumed = consumeBytesAfter(i, length - dtcLen);
						if (consumed > 0) {
							dtc.updateRecord();
							shiftOffsets(i + 1, -consumed, 0);
							didChange = true;
						}
					}
					if (dtc.getLength() != length) {
						warn = true;
					}
				}
			}
			if (didChange) {
				adjustInternalAlignment(false);
				notifySizeChanged(); // notifies parents
			}
			if (warn) {
				Msg.warn(this,
					"Failed to resize one or more structure components: " + getPathName());
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected void fixupComponents() {
		if (isInternallyAligned()) {
			// Do not notify parents
			if (adjustComponents(false)) {
				dataMgr.dataTypeChanged(this);
			}
			return;
		}
		boolean didChange = false;
		boolean warn = false;
		int n = components.size();
		for (int i = 0; i < n; i++) {
			DataTypeComponentDB dtc = components.get(i);
			DataType dt = dtc.getDataType();
			if (dt instanceof BitFieldDataType) {
				// TODO: could get messy
				continue;
			}
			int dtcLen = dtc.getLength();
			int length = dt.getLength();
			if (length <= 0) {
				length = dtcLen;
			}
			if (dtcLen != length) {
				if (length < dtcLen) {
					dtc.setLength(length, true);
					shiftOffsets(i + 1, dtcLen - length, 0);
					didChange = true;
				}
				else if (length > dtcLen) {
					int consumed = consumeBytesAfter(i, length - dtcLen);
					if (consumed > 0) {
						dtc.updateRecord();
						shiftOffsets(i + 1, -consumed, 0);
						didChange = true;
					}
				}
				if (dtc.getLength() != length) {
					warn = true;
				}
			}
		}
		if (didChange) {
			// Do not notify parents
			adjustInternalAlignment(false);
			dataMgr.dataTypeChanged(this);
		}
		if (warn) {
			Msg.warn(this, "Failed to resize one or more structure components: " + getPathName());
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			adjustInternalAlignment(true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isEquivalent(DataType dataType) {
		if (dataType == this) {
			return true;
		}
		if (!(dataType instanceof Structure)) {
			return false;
		}

		checkIsValid();
		if (resolving) { // actively resolving children
			if (dataType.getUniversalID().equals(getUniversalID())) {
				return true;
			}
			return DataTypeUtilities.equalsIgnoreConflict(getPathName(), dataType.getPathName());
		}

		Boolean isEquivalent = dataMgr.getCachedEquivalence(this, dataType);
		if (isEquivalent != null) {
			return isEquivalent;
		}

		try {
			isEquivalent = false;
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
			isEquivalent = true;
		}
		finally {
			dataMgr.putCachedEquivalence(this, dataType, isEquivalent);
		}
		return true;
	}

	/**
	 *
	 * @param definedComponentIndex the index of the defined component that is consuming the bytes.
	 * @param numBytes the number of undefined bytes to consume
	 * @return the number of bytes actually consumed
	 */
	private int consumeBytesAfter(int definedComponentIndex, int numBytes) {
		DataTypeComponentDB thisDtc = components.get(definedComponentIndex);
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
			thisDtc.setLength(thisLen + numBytes, true);
			return numBytes;
		}
		thisDtc.setLength(thisLen + available, true);
		return available;
	}

	private int getLastDefinedComponentIndex() {
		if (components.size() == 0) {
			return 0;
		}
		DataTypeComponentDB dataTypeComponentDB = components.get(components.size() - 1);
		return dataTypeComponentDB.getOrdinal();
	}

	private void shiftOffsets(int definedComponentIndex, int deltaOrdinal, int deltaOffset) {
		for (int i = definedComponentIndex; i < components.size(); i++) {
			DataTypeComponentDB dtc = components.get(i);
			shiftOffset(dtc, deltaOrdinal, deltaOffset);
		}
		structLength += deltaOffset;
		if (!isInternallyAligned()) {
			numComponents += deltaOrdinal;
		}
		record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
		record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
		try {
			compositeAdapter.updateRecord(record, true);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	protected void shiftOffset(DataTypeComponentDB dtc, int deltaOrdinal, int deltaOffset) {
		dtc.setOffset(dtc.getOffset() + deltaOffset, false);
		dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal, false);
		dtc.updateRecord();
	}

	/**
	 * Replace the indicated component with a new component containing the specified data type.
	 * Flex-array component not handled.
	 * 
	 * @param origDtc the original data type component in this structure.
	 * @param resolvedDataType the data type of the new component
	 * @param length the length of the new component
	 * @param name the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if the new component couldn't fit.
	 */
	private DataTypeComponent replaceComponent(DataTypeComponent origDtc, DataType resolvedDataType,
			int length, String name, String comment, boolean doNotify) {

// FIXME: Unsure how to support replace operation with bit-fields.  Within unaligned structure 
// the packing behavior for bit-fields prevents a one-for-one replacement and things may shift
// around which the unaligned structure tries to avoid.  Insert and delete are less of a concern
// since movement already can occur, although insert at offset may not retain the offset if it 
// interacts with bit-fields.

		try {
			int ordinal = origDtc.getOrdinal();
			int newOffset = origDtc.getOffset();
			int dtcLength = origDtc.getLength();
			int bytesNeeded = length - dtcLength;
			int deltaOrdinal = -bytesNeeded;
			int origStructLength = structLength;
			if (!isInternallyAligned() && bytesNeeded > 0) {
				int bytesAvailable = getNumUndefinedBytes(ordinal + 1);
				if (bytesAvailable < bytesNeeded) {
					if (ordinal == getLastDefinedComponentIndex()) {
						growStructure(bytesNeeded - bytesAvailable);
					}
					else {
						throw new IllegalArgumentException("Not enough undefined bytes to fit " +
							resolvedDataType.getPathName() + " in structure " + getPathName() +
							" at offset 0x" + Integer.toHexString(newOffset) + "." + " It needs " +
							(bytesNeeded - bytesAvailable) + " more byte(s) to be able to fit.");
					}
				}
			}
			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(resolvedDataType), key,
				length, ordinal, newOffset, name, comment);
			resolvedDataType.addParent(this);
			DataTypeComponentDB newDtc =
				new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			int index;
			if (isInternallyAligned()) {
				index = ordinal;
			}
			else {
				index = Collections.binarySearch(components, Integer.valueOf(ordinal),
					ordinalComparator);
			}
			if (index < 0) {
				index = -index - 1;
			}
			else {
				DataTypeComponentDB dataTypeComponentDB = components.get(index); // TODO Remove this.
				dataTypeComponentDB.getDataType().removeParent(this);
				DataTypeComponentDB dtc = components.remove(index);
				componentAdapter.removeRecord(dtc.getKey());
			}
			components.add(index, newDtc);
			if (deltaOrdinal != 0) {
				shiftOffsets(index + 1, deltaOrdinal, 0);
			}
			if (structLength != origStructLength) {
				record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
				compositeAdapter.updateRecord(record, true);
				adjustInternalAlignment(false);
				notifySizeChanged();
			}
			else if (doNotify) {
				dataMgr.dataTypeChanged(this);
			}
			return newDtc;
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return null;
	}

	/**
	 * Gets the number of Undefined bytes beginning at the indicated component ordinal. Undefined
	 * bytes that have a field name or comment specified are also included.
	 * 
	 * @param ordinal the component ordinal to begin checking at.
	 * @return the number of contiguous undefined bytes
	 */
	private int getNumUndefinedBytes(int ordinal) {
		if (isInternallyAligned()) {
			return 0;
		}
		if (ordinal >= numComponents) {
			return 0;
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(ordinal), ordinalComparator);
		DataTypeComponentDB dtc = null;
		if (idx < 0) {
			idx = -idx - 1;
			if (idx >= components.size()) {
				return numComponents - ordinal;
			}
			dtc = components.get(idx);
			return dtc.getOrdinal() - ordinal;
		}
		return 0;
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (oldDt == this) {
			return;
		}
		lock.acquire();
		try {
			checkDeleted();
			DataType replacementDt = newDt;
			try {
				validateDataType(replacementDt);
				if (!(replacementDt instanceof DataTypeDB) ||
					(replacementDt.getDataTypeManager() != dataMgr)) {
					replacementDt = resolve(replacementDt);
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
					componentAdapter.removeRecord(flexibleArrayComponent.getKey());
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

				DataTypeComponentDB comp = components.get(i);
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
							"Invalid replacement type " + newDt.getName() +
								", removing component " + comp.getDataType().getName() + ": " +
								getPathName());
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
					componentAdapter.removeRecord(comp.getKey());
					changed = true;
				}
			}
			if (changed) {
				adjustInternalAlignment(false);
				notifySizeChanged();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void setComponentDataType(DataTypeComponentDB comp, DataType replacementDt,
			int nextIndex) {

		comp.getDataType().removeParent(this);
		comp.setDataType(replacementDt);
		replacementDt.addParent(this);

		if (isInternallyAligned()) {
			return; // caller must invoke adjustInternalAlignment
		}

		int len = replacementDt.getLength();
		int oldLen = comp.getLength();
		if (len > 0) {
			if (len < oldLen) {
				comp.setLength(len, true);
				shiftOffsets(nextIndex, oldLen - len, 0);
			}
			else if (len > oldLen) {
				int bytesAvailable = getNumUndefinedBytes(comp.getOrdinal() + 1);
				int bytesNeeded = len - oldLen;
				if (bytesNeeded <= bytesAvailable) {
					comp.setLength(len, true);
					shiftOffsets(nextIndex, -bytesNeeded, 0);
				}
				else if (comp.getOrdinal() == getLastDefinedComponentIndex()) {
					// we are the last defined component, grow structure
					doGrowStructure(bytesNeeded - bytesAvailable);
					comp.setLength(len, true);
					shiftOffsets(nextIndex, -bytesNeeded, 0);
				}
				else {
					comp.setLength(oldLen + bytesAvailable, true);
					shiftOffsets(nextIndex, -bytesAvailable, 0);
				}
			}
		}
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// do nothing
	}

	@Override
	public void deleteAll() {
		lock.acquire();
		try {
			checkDeleted();

			if (flexibleArrayComponent != null) {
				flexibleArrayComponent.getDataType().removeParent(this);
				componentAdapter.removeRecord(flexibleArrayComponent.getKey());
				flexibleArrayComponent = null;
			}

			for (DataTypeComponentDB dtc : components) {
				dtc.getDataType().removeParent(this);
				try {
					componentAdapter.removeRecord(dtc.getKey());
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
			}
			components.clear();
			structLength = 0;
			numComponents = 0;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, 0);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, 0);
			compositeAdapter.updateRecord(record, true);
			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * <code>ComponentComparator</code> provides ability to compare two DataTypeComponent objects
	 * based upon their ordinal. Intended to be used to sort components based upon ordinal.
	 */
	private static class ComponentComparator implements Comparator<DataTypeComponent> {
		@Override
		public int compare(DataTypeComponent dtc1, DataTypeComponent dtc2) {
			return dtc1.getOrdinal() - dtc2.getOrdinal();
		}
	}

	/**
	 * Adjust the alignment, packing and padding of components within this structure based upon the
	 * current alignment and packing attributes for this structure. This method should be called to
	 * basically fix up the layout of the internal components of the structure after other code has
	 * changed the attributes of the structure. <BR>
	 * When switching between internally aligned and unaligned this method corrects the component
	 * ordinal numbering also.
	 * 
	 * @param notify if true this method will do data type change notification when it changes the
	 *            layout of the components or when it changes the overall size of the structure.
	 * @return true if the structure was changed by this method.
	 */
	private boolean adjustComponents(boolean notify) {

		lock.acquire();
		try {
			checkDeleted();

			boolean changed = false;
			alignment = -1;

			if (!isInternallyAligned()) {
				changed |= adjustUnalignedComponents();
				if (notify && changed) {
					dataMgr.dataTypeChanged(this);
				}
				return changed;
			}

			int oldLength = structLength;

			StructurePackResult packResult =
				AlignedStructurePacker.packComponents(this, components);
			changed = packResult.componentsChanged;

			// Adjust the structure
			changed |= updateComposite(packResult.numComponents, packResult.structureLength,
				packResult.alignment, false);

			if (changed) {
				if (notify) {
					if (oldLength != structLength) {
						notifySizeChanged();
					}
					else {
						dataMgr.dataTypeChanged(this);
					}
				}
				return true;
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	private boolean adjustUnalignedComponents() {
		boolean changed = false;
		int componentCount = 0;
		int currentOffset = 0;
		for (DataTypeComponentDB dataTypeComponent : components) {
			int componentLength = dataTypeComponent.getLength();
			int componentOffset = dataTypeComponent.getOffset();
			int numUndefinedsBefore = componentOffset - currentOffset;
			if (numUndefinedsBefore > 0) {
				componentCount += numUndefinedsBefore;
			}
			currentOffset = componentOffset + componentLength;
			if (dataTypeComponent.getOrdinal() != componentCount) {
				dataTypeComponent.setOrdinal(componentCount, true);
				changed = true;
			}
			componentCount++;
		}
		int numUndefinedsAfter = structLength - currentOffset;
		componentCount += numUndefinedsAfter;
		if (updateNumComponents(componentCount)) {
			changed = true;
		}
		return changed;
	}

	private boolean updateNumComponents(int currentNumComponents) {
		boolean compositeChanged = false;
		if (numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
			compositeChanged = true;
		}
		if (compositeChanged) {
			try {
				compositeAdapter.updateRecord(record, true);
				return true;
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		return false;
	}

	private boolean updateComposite(int currentNumComponents, int currentLength,
			int currentAlignment, boolean setLastChangeTime) {
		boolean compositeChanged = false;
		if (numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
			compositeChanged = true;
		}
		if (structLength != currentLength) {
			structLength = currentLength;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeChanged = true;
		}
		if (alignment != currentAlignment) {
			alignment = currentAlignment;
			compositeChanged = true;
		}
		if (compositeChanged) {
			try {
				compositeAdapter.updateRecord(record, setLastChangeTime);
				return true;
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		return false;
	}

	@Override
	public void realign() {
		if (isInternallyAligned()) {
			adjustInternalAlignment(true);
		}
	}

	@Override
	public void pack(int packingSize) {
		setPackingValue(packingSize);
	}

	@Override
	protected void adjustInternalAlignment(boolean notify) {
		adjustComponents(notify);
	}

	@Override
	public boolean hasFlexibleArrayComponent() {
		return flexibleArrayComponent != null;
	}

	@Override
	public DataTypeComponentDB getFlexibleArrayComponent() {
		return flexibleArrayComponent;
	}

	private boolean isInvalidFlexArrayDataType(DataType dataType) {
		return (dataType == null || dataType == DataType.DEFAULT ||
			dataType instanceof BitFieldDataType || dataType instanceof Dynamic ||
			dataType instanceof FactoryDataType);
	}

	@Override
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) throws IllegalArgumentException {
		if (isInvalidFlexArrayDataType(flexType)) {
			throw new IllegalArgumentException(
				"Unsupported flexType: " + flexType.getDisplayName());
		}
		try {
			return doAddFlexArray(flexType, name, comment, true);
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	@Override
	public void clearFlexibleArrayComponent() {
		lock.acquire();
		try {
			checkDeleted();
			if (flexibleArrayComponent == null) {
				return;
			}

			DataTypeComponentDB dtc = flexibleArrayComponent;
			flexibleArrayComponent = null;
			dtc.getDataType().removeParent(this);
			try {
				componentAdapter.removeRecord(dtc.getKey());
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
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
