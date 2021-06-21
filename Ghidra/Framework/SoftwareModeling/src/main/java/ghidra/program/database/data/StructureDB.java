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

import db.DBRecord;
import db.Field;
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
class StructureDB extends CompositeDB implements StructureInternal {

	private int structLength;
	private int structAlignment;  // reflects stored alignment, -1 if not yet stored
	private int computedAlignment = -1; // cached alignment if not yet stored

	private int numComponents; // If packed, this does not include the undefined components.
	private List<DataTypeComponentDB> components;
	private DataTypeComponentDB flexibleArrayComponent;

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

		Collections.sort(components, ComponentComparator.INSTANCE);

		structLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);
		structAlignment = record.getIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL);
		computedAlignment = -1;
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
			boolean validatePackAndNotify)
			throws DataTypeDependencyException, IllegalArgumentException {

		// TODO: May want to standardize flex-array use with StructureDataType

		lock.acquire();
		try {
			checkDeleted();

			if (validatePackAndNotify) {
				dataType = validateDataType(dataType);
				dataType = resolve(dataType);
				checkAncestry(dataType);
			}

			DataTypeComponentDB dtc = null;
			try {
				if (dataType == DataType.DEFAULT) {
					// FIXME: verify - does not appear to modify structure
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
				if (!isPackingEnabled() && length > 0) {
					structureGrowth = length;
				}

				++numComponents;
				structLength += structureGrowth;

				if (validatePackAndNotify) {
					repack(false, false); // may not recognize length change
					record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL,
						numComponents);
					record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
					compositeAdapter.updateRecord(record, true); // update timestamp
					notifySizeChanged(false);
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
			boolean validatePackAndNotify)
			throws DataTypeDependencyException, IllegalArgumentException {

		// TODO: May want to standardize implementation with StructureDataType

		lock.acquire();
		try {
			checkDeleted();

			if (validatePackAndNotify) {

				if (isInvalidFlexArrayDataType(dataType)) {
					throw new IllegalArgumentException(
						"Unsupported flexType: " + dataType.getDisplayName());
				}

				validateDataType(dataType);
				dataType = resolve(dataType);
				checkAncestry(dataType);
			}

			DataTypeComponentDB dtc = null;
			try {

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

				if (validatePackAndNotify) {
					repack(false, false);
					compositeAdapter.updateRecord(record, true);
					notifySizeChanged(false);
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
		if (isPackingEnabled()) {
			return;
		}
		lock.acquire();
		try {
			checkDeleted();
			doGrowStructure(amount);
			repack(false, false);
			notifySizeChanged(false);
		}
		finally {
			lock.release();
		}
	}

	private void doGrowStructure(int amount) {
		if (!isPackingEnabled()) {
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
				throw new IndexOutOfBoundsException(ordinal);
			}
			if (ordinal == numComponents) {
				return add(dataType, length, name, comment);
			}
			dataType = validateDataType(dataType);

			dataType = resolve(dataType);
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
				// assume non-packed insert of DEFAULT
				shiftOffsets(idx, 1, 1);
				notifySizeChanged(false);
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
			repack(false, false);
			notifySizeChanged(false);
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
			throws InvalidDataTypeException, IndexOutOfBoundsException {

		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal > numComponents) {
				throw new IndexOutOfBoundsException(ordinal);
			}

			if (!isPackingEnabled()) {
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
				bigEndian ? BitOffsetComparator.INSTANCE_BE : BitOffsetComparator.INSTANCE_LE;
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

			if (isPackingEnabled()) {
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

			adjustNonPackedComponents(true);
			notifySizeChanged(false);
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
				doDelete(idx); // updates timestamp
			}
			else {
				// assume non-packed removal of DEFAULT
				idx = -idx - 1;
				shiftOffsets(idx, -1, -1); // updates timestamp
			}
			repack(false, false);
			notifySizeChanged(false);
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
		if (isPackingEnabled()) {
			return;
		}
		int shiftAmount = dtc.isBitFieldComponent() ? 0 : dtc.getLength();
		shiftOffsets(index, -1, -shiftAmount);
	}

	@Override
	public void delete(Set<Integer> ordinals) {
		lock.acquire();
		try {
			checkDeleted();

			if (ordinals.isEmpty()) {
				return;
			}

			boolean bitFieldRemoved = false;

			TreeSet<Integer> treeSet = null;
			if (!isPackingEnabled()) {
				// treeSet only used to track undefined filler removal
				treeSet = new TreeSet<>(ordinals);
			}

			List<DataTypeComponentDB> newComponents = new ArrayList<>();
			int ordinalAdjustment = 0;
			int offsetAdjustment = 0;
			int lastDefinedOrdinal = -1;
			for (DataTypeComponentDB dtc : components) {
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
				Set<Integer> removedFillerSet =
					treeSet.subSet(lastDefinedOrdinal + 1, numComponents);
				if (!removedFillerSet.isEmpty()) {
					int undefinedRemoveCount = removedFillerSet.size();
					ordinalAdjustment -= undefinedRemoveCount;
					offsetAdjustment -= undefinedRemoveCount;
				}
			}

			components = newComponents;
			updateNumComponents(numComponents + ordinalAdjustment);

			if (isPackingEnabled()) {
				if (!repack(false, true)) {
					dataMgr.dataTypeChanged(this, false);
				}
			}
			else {
				structLength += offsetAdjustment;
				if (bitFieldRemoved) {
					repack(false, false);
				}
				notifySizeChanged(false);
			}
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
				throw new IndexOutOfBoundsException(ordinal);
			}
			if (isPackingEnabled()) {
				return components.get(ordinal);
			}
			int idx =
				Collections.binarySearch(components, Integer.valueOf(ordinal),
					OrdinalComparator.INSTANCE);
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
	 * WARNING! copying non-packed structures which contain bitfields can produce invalid results when
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
	 * cloning non-packed structures which contain bitfields can produce invalid results when
	 * switching endianess due to the differences in packing order.
	 * 
	 * @param dtm target data type manager
	 * @return cloned structure
	 */
	@Override
	public Structure clone(DataTypeManager dtm) {
		StructureDataType struct =
			new StructureDataType(getCategoryPath(), getName(), structLength, getUniversalID(),
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
	protected int getComputedAlignment(boolean updateRecord) {
		if (structAlignment > 0) {
			return structAlignment;
		}
		if (computedAlignment <= 0) {
			if (isPackingEnabled()) {
				StructurePackResult packResult = AlignedStructureInspector.packComponents(this);
				computedAlignment = packResult.alignment;
			}
			else {
				computedAlignment = getNonPackedAlignment();
			}
		}
		if (updateRecord) {
			// perform lazy update of stored computed alignment
			record.setIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL, computedAlignment);
			try {
				compositeAdapter.updateRecord(record, false);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
			structAlignment = computedAlignment;
			computedAlignment = -1;
			return structAlignment;
		}
		return computedAlignment;
	}

	@Override
	public boolean isZeroLength() {
		return structLength == 0;
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
	public boolean hasLanguageDependantLength() {
		return isPackingEnabled();
	}

	@Override
	public void clearComponent(int ordinal) {
		lock.acquire();
		try {
			checkDeleted();
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
					shiftOffsets(idx, len - 1, 0); // updates timestamp
				}
				else {
					compositeAdapter.updateRecord(record, true); // update timestamp
				}
				repack(false, false);
				dataMgr.dataTypeChanged(this, false);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
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
	 * @param index defined component index
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
	 * @param index defined component index
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
				Collections.binarySearch(components, Integer.valueOf(offset),
					OffsetComparator.INSTANCE);

			int offsetDelta = 0;
			int ordinalDelta = 0;
			if (index < 0) {
				index = -index - 1;
				--ordinalDelta;
				offsetDelta = -1;
				shiftOffsets(index, ordinalDelta, offsetDelta); // updates timestamp
			}
			else {
				index = advanceToLastComponentContainingOffset(index, offset);
				DataTypeComponentDB dtc = components.get(index);
				while (dtc.containsOffset(offset)) {
					doDelete(index); // updates timestamp
					if (--index < 0) {
						break;
					}
					dtc = components.get(index);
				}
			}
			repack(false, false);
			notifySizeChanged(false);
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
				Collections.binarySearch(components, Integer.valueOf(offset),
					OffsetComparator.INSTANCE);
			if (index >= 0) {
				DataTypeComponent dtc = components.get(index);
				if (dtc.isBitFieldComponent()) {
					index = backupToFirstComponentContainingOffset(index, offset);
					dtc = components.get(index);
				}
				return dtc;
			}
			else if (isPackingEnabled()) {
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
			dataType = validateDataType(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

			if ((offset > structLength) && !isPackingEnabled()) {
				numComponents = numComponents + (offset - structLength);
				structLength = offset;
			}

			int index =
				Collections.binarySearch(components, Integer.valueOf(offset),
					OffsetComparator.INSTANCE);

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
				// assume non-packed insert of DEFAULT
				shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
				repack(false, false);
				notifySizeChanged(false);
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
			repack(false, false);
			notifySizeChanged(false);
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
			String comment) {
		lock.acquire();
		try {
			checkDeleted();

			if (ordinal < 0 || ordinal >= numComponents) {
				throw new IndexOutOfBoundsException(ordinal);
			}

			dataType = validateDataType(dataType);

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
				replaceComponent(origDtc, dataType, length, name, comment);

			repack(false, false);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeAdapter.updateRecord(record, true);
			notifySizeChanged(false);

			return replaceComponent;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
			return null;
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

			dataType = validateDataType(dataType);

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
				replaceComponent(origDtc, dataType, length, name, comment);

			repack(false, false);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeAdapter.updateRecord(record, true);
			notifySizeChanged(false);

			return replaceComponent;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
			return null;
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
		if (!(dataType instanceof StructureInternal)) {
			throw new IllegalArgumentException();
		}
		lock.acquire();
		boolean isResolveCacheOwner = dataMgr.activateResolveCache();
		try {
			checkDeleted();
			doReplaceWith((StructureInternal) dataType, true);
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
	 * Replaces the internal components of this structure with components of the given structure
	 * including packing and alignment settings.
	 * 
	 * @param struct structure to be copied
	 * @param notify provide notification if true
	 * @throws DataTypeDependencyException if circular dependency detected
	 * @throws IOException if database IO error occurs
	 */
	void doReplaceWith(StructureInternal struct, boolean notify)
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

		for (DataTypeComponentDB dtc : components) {
			dtc.getDataType().removeParent(this);
			componentAdapter.removeRecord(dtc.getKey());
		}

		if (flexibleArrayComponent != null) {
			flexibleArrayComponent.getDataType().removeParent(this);
			componentAdapter.removeRecord(flexibleArrayComponent.getKey());
			flexibleArrayComponent = null;
		}

		components.clear();
		numComponents = 0;
		structLength = 0;
		structAlignment = -1;
		computedAlignment = -1;

		doSetPackingAndAlignment(struct); // updates timestamp

		if (struct.isPackingEnabled()) {
			doReplaceWithAligned(struct, resolvedDts);
		}
		else {
			doReplaceWithUnaligned(struct, resolvedDts);
		}

		if (flexComponent != null) {
			doAddFlexArray(resolvedFlexDt, flexComponent.getFieldName(), flexComponent.getComment(),
				false);
		}

		repack(false, false);

		// must force record update
		record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
		record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
		record.setIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL, structAlignment);
		compositeAdapter.updateRecord(record, notify);

		if (notify) {
			notifySizeChanged(false);
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
		if (struct.isZeroLength()) {
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
		repack(false, false);
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
			boolean changed = false;
			if (flexibleArrayComponent != null && flexibleArrayComponent.getDataType() == dt) {
				flexibleArrayComponent.getDataType().removeParent(this);
				componentAdapter.removeRecord(flexibleArrayComponent.getKey());
				flexibleArrayComponent = null;
				changed = true;
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
// FIXME: Consider replacing with undefined type instead of removing (don't remove bitfield)
					components.remove(i);
					shiftOffsets(i, dtc.getLength() - 1, 0); // ordinals only
					componentAdapter.removeRecord(dtc.getKey());
					--numComponents; // may be revised by repack
					changed = true;
				}
			}
			if (changed && !repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
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
			if (isPackingEnabled()) {
				if (!repack(true, true)) {
					dataMgr.dataTypeChanged(this, true);
				}
				return;
			}
			int oldLength = structLength;
			boolean changed = false;
			boolean warn = false;
			int n = components.size();
			for (int i = 0; i < n; i++) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.getDataType() == dt) {
					// assume no impact to bitfields since base types should not change size
					int dtcLen = dtc.getLength();
					int length = dt.getLength();
					if (length <= 0) {
						length = dtcLen;
					}
					if (length < dtcLen) {
						dtc.setLength(length, true);
						shiftOffsets(i + 1, dtcLen - length, 0);
						changed = true;
					}
					else if (length > dtcLen) {
						int consumed = consumeBytesAfter(i, length - dtcLen);
						if (consumed > 0) {
							dtc.updateRecord();
							shiftOffsets(i + 1, -consumed, 0);
							changed = true;
						}
					}
					if (dtc.getLength() != length) {
						warn = true;
					}
				}
			}
			if (warn) {
				Msg.warn(this,
					"Failed to resize one or more structure components: " + getPathName());
			}
			if (changed) {
				repack(false, false);
				if (oldLength != structLength) {
					notifySizeChanged(false);
				}
				else {
					dataMgr.dataTypeChanged(this, false);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected void fixupComponents() throws IOException {
		boolean isPacked = isPackingEnabled();
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
				if (isPacked) {
					dtc.setLength(length, true);
					didChange = true;
				}
				else if (length < dtcLen) {
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
			// Do not notify parents - must be invoked in composite dependency order
			repack(false, false);
			compositeAdapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this, false);
		}
		if (warn) {
			Msg.warn(this, "Failed to resize one or more structure components: " + getPathName());
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		lock.acquire();
		try {
			if (isPackingEnabled()) {
				checkDeleted();
				repack(true, true);
			}
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
		if (!(dataType instanceof StructureInternal)) {
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
			StructureInternal struct = (StructureInternal) dataType;
			int otherLength = struct.isZeroLength() ? 0 : struct.getLength();
			int packing = getStoredPackingValue();
			if (packing != struct.getStoredPackingValue() ||
				getStoredMinimumAlignment() != struct.getStoredMinimumAlignment() ||
				(packing == NO_PACKING && structLength != otherLength)) {
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
		if (!isPackingEnabled()) {
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
	 * @throws IOException if database IO error occurs
	 */
	private DataTypeComponent replaceComponent(DataTypeComponent origDtc, DataType resolvedDataType,
			int length, String name, String comment) throws IOException {

// FIXME: Unsure how to support replace operation with bit-fields.  Within non-packed structure 
// the packing behavior for bit-fields prevents a one-for-one replacement and things may shift
// around which the non-packed structure tries to avoid.  Insert and delete are less of a concern
// since movement already can occur, although insert at offset may not retain the offset if it 
// interacts with bit-fields.

		int ordinal = origDtc.getOrdinal();
		int newOffset = origDtc.getOffset();
		int dtcLength = origDtc.getLength();
		int bytesNeeded = length - dtcLength;
		int deltaOrdinal = -bytesNeeded;
		if (!isPackingEnabled() && bytesNeeded > 0) {
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
		DataTypeComponentDB newDtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
		int index;
		if (isPackingEnabled()) {
			index = ordinal;
		}
		else {
			index =
				Collections.binarySearch(components, Integer.valueOf(ordinal),
					OrdinalComparator.INSTANCE);
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
		return newDtc;
	}

	/**
	 * Gets the number of Undefined bytes beginning at the indicated component ordinal. Undefined
	 * bytes that have a field name or comment specified are also included.
	 * 
	 * @param ordinal the component ordinal to begin checking at.
	 * @return the number of contiguous undefined bytes
	 */
	private int getNumUndefinedBytes(int ordinal) {
		if (isPackingEnabled()) {
			return 0;
		}
		if (ordinal >= numComponents) {
			return 0;
		}
		int idx = Collections.binarySearch(components, Integer.valueOf(ordinal),
			OrdinalComparator.INSTANCE);
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
					if (replacementDt == DEFAULT && isPackingEnabled()) {
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
				repack(false, false);
				compositeAdapter.updateRecord(record, true); // update timestamp
				notifySizeChanged(false);
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

		int oldLen = comp.getLength();
		int len = replacementDt.getLength();
		if (len < 1) {
			len = oldLen;
		}

		comp.getDataType().removeParent(this);

		if (isPackingEnabled()) {
			comp.setLength(len, false); // do before record save below
		}
		comp.setDataType(replacementDt); // saves component record
		replacementDt.addParent(this);

		if (isPackingEnabled()) {
			return;
		}

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
			notifySizeChanged(false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Perform structure member repack.
	 * Perform lazy update of stored alignment introduced with v5 adapter.
	 */
	@Override
	protected boolean repack(boolean isAutoChange, boolean notify) {

		lock.acquire();
		try {
			checkDeleted();

			int oldLength = structLength;
			int oldAlignment = getComputedAlignment(true); // ensure that alignment has been stored
			
			computedAlignment = -1; // clear cached alignment
			
			boolean changed;
			if (!isPackingEnabled()) {
				changed = adjustNonPackedComponents(!isAutoChange);
			}
			else {
				StructurePackResult packResult =
					AlignedStructurePacker.packComponents(this, components);
				changed = packResult.componentsChanged;
				changed |= updateComposite(packResult.numComponents, packResult.structureLength,
					packResult.alignment, !isAutoChange);
			}
			
			if (changed && notify) {
				if (oldLength != structLength) {
					notifySizeChanged(isAutoChange);
				}
				else if (oldAlignment != structAlignment) {
					notifyAlignmentChanged(isAutoChange);
				}
				dataMgr.dataTypeChanged(this, isAutoChange);
			}
			return changed;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Updates non-packed component ordinals and numComponents.
	 * If numComponents changes record update will be performed
	 * with new timestamp.
	 * @return true if change detected else false
	 */
	private boolean adjustNonPackedComponents(boolean setLastChangeTime) {
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
		changed |= updateComposite(componentCount, structLength, getNonPackedAlignment(),
			setLastChangeTime);
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
			setLastChangeTime = true;
			compositeChanged = true;
		}
		if (structLength != currentLength) {
			structLength = currentLength;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeChanged = true;
		}
		if (structAlignment != currentAlignment) {
			structAlignment = currentAlignment;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL, structAlignment);
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
			repack(false, false);
			compositeAdapter.updateRecord(record, true);
			notifySizeChanged(false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

}
