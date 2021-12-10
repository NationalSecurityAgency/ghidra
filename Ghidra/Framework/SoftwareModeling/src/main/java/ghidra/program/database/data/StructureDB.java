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
			DBRecord oldFlexArrayRecord = null;
			Field[] ids = componentAdapter.getComponentIdsInComposite(key);
			for (Field id : ids) {
				DBRecord rec = componentAdapter.getRecord(id.getLongValue());
				if (rec.getIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL) < 0) {
					// old flex-array component record - defer migration (see below)
					oldFlexArrayRecord = rec;
					continue;
				}
				DataTypeComponentDB component =
					new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
				components.add(component);
			}

			Collections.sort(components, ComponentComparator.INSTANCE);

			structLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);
			structAlignment = record.getIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL);
			computedAlignment = -1;
			numComponents = isPackingEnabled() ? components.size()
					: record.getIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL);

			if (oldFlexArrayRecord != null) {
				migrateOldFlexArray(oldFlexArrayRecord);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	/**
	 * Eliminate use of old trailing flex-array specification which is now specified using
	 * a zero-element array.  Due to the specification of a new array datatype this must handle
	 * two cases when an old flex-array component is exists:
	 * <ol>
	 * <li>read-only case: associated {@link DataTypeManagerDB} is not updateable.  This is the normal
	 * case for an open archive.  A non-DB ArrayDataType must be employed with an immutable
	 * {@link DataTypeProxyComponentDB} in place of the flex-array component.</li>
	 * <li>upgrade (open for update with open transaction): the flex-array record is modified to
	 * to indicate an appropriate resolved zero-element array.
	 * </ol>
	 * <p>
	 * NOTE: When {@link DataTypeManagerDB} is instantiated for update an upgrade must be forced based upon the
	 * {@link CompositeDBAdapter#isFlexArrayMigrationRequired()} indicator.  The upgrade logic
	 * (see {@link DataTypeManagerDB#migrateOldFlexArrayComponentsIfRequired(ghidra.util.task.TaskMonitor)}) 
	 * istantiates all structures within the databases with an open transaaction allowing this method
	 * to perform the neccessary flex-array record migration.
	 * <p>
	 * NOTE: The offset of the migrated flex array component and structure length may change during upgrade 
	 * when packing is enabled when the original packed structure length did not properly factor the flex-array
	 * alignment.  Repack does not occur in the read-only case. 
	 * 
	 * @param oldFlexArrayRecord record which corresponds to an olf flex-array component
	 * @throws IOException if a database error occurs
	 */
	private void migrateOldFlexArray(DBRecord oldFlexArrayRecord) throws IOException {
		long id = oldFlexArrayRecord.getLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL);
		DataType dt = dataMgr.getDataType(id); // could be BadDataType if built-in type is missing

		// use zero-element array (need positive element length if dt is BadDataType)
		dt = new ArrayDataType(dt, 0, 1, dataMgr);

		boolean repack = false;

		DataTypeComponentDB component;
		if (dataMgr.isUpdatable()) {
			if (!dataMgr.isTransactionActive()) {
				throw new AssertException(
					"Structure flex-array component should have been migrated during required upgrade: " +
						getPathName());
			}
			dt = dataMgr.resolve(dt, null); // use zero-length array
			oldFlexArrayRecord.setIntValue(ComponentDBAdapter.COMPONENT_ORDINAL_COL,
				numComponents++);
			oldFlexArrayRecord.setIntValue(ComponentDBAdapter.COMPONENT_OFFSET_COL,
				structLength);
			oldFlexArrayRecord.setLongValue(ComponentDBAdapter.COMPONENT_DT_ID_COL,
				dataMgr.getID(dt));
			componentAdapter.updateRecord(oldFlexArrayRecord);

			component = new DataTypeComponentDB(dataMgr, componentAdapter, this,
				oldFlexArrayRecord);

			// Update component count (flex-array had been excluded prviously)
			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL,
				numComponents);
			compositeAdapter.updateRecord(record, false);
			repack = isPackingEnabled();
		}
		else {
			// read-only mode must use proxy component with zero-length array
			String fieldName =
				oldFlexArrayRecord.getString(ComponentDBAdapter.COMPONENT_FIELD_NAME_COL);
			String comment =
				oldFlexArrayRecord.getString(ComponentDBAdapter.COMPONENT_COMMENT_COL);
			component = new DataTypeProxyComponentDB(dataMgr, this, numComponents++,
				structLength, dt, 0, fieldName, comment);
		}

		components.add(component);

		if (repack) {
			repack(false, false); // repack during upgrade only when packing enabled
		}
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
					// assume non-packed structure - structre will grow by 1-byte below
					dtc = new DataTypeComponentDB(dataMgr, this, numComponents, structLength);
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
				if (structureGrowth != 0 && !isPackingEnabled() && length > 0) {
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
		if (isPackingEnabled()) {
			throw new AssertException("only valid for non-packed");
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
				doDeleteWithComponentShift(idx, false); // updates timestamp
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

	/**
	 * Removes a defined component at the specified index without
	 * any alteration to other components. 
	 * @param index defined component index
	 * @return the defined component which was removed.
	 * @throws IOException if an IO error occurs
	 */
	private DataTypeComponentDB doDelete(int index) throws IOException {
		DataTypeComponentDB dtc = components.remove(index);
		dtc.getDataType().removeParent(this);
		componentAdapter.removeRecord(dtc.getKey());
		return dtc;
	}

	/**
	 * Removes a defined component at the specified index.
	 * If this corresponds to a zero-length or bit-field component it will 
	 * be cleared without an offset shift to the remaining components.  Removal of
	 * other component types will result in an offset and ordinal shift
	 * to the remaining components.  In the case of a non-packed
	 * structure, the resulting shift will cause in a timestamp change
	 * for this structure.
	 * @param index defined component index
	 * @param disableOffsetShift if false, and component is not a bit-field, an offset shift
	 * and possible structure length change will be performed for non-packed structure.
	 */
	private void doDeleteWithComponentShift(int index, boolean disableOffsetShift) {
		DataTypeComponentDB dtc = null;
		try {
			dtc = doDelete(index);
		}
		catch (IOException e) {
			dataMgr.dbError(e); // does not return
		}
		if (isPackingEnabled()) {
			return;
		}
		int shiftAmount = (disableOffsetShift || dtc.isBitFieldComponent()) ? 0 : dtc.getLength();
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
			updateComposite(numComponents + ordinalAdjustment, -1, -1, true); // update numComponents only

			if (isPackingEnabled()) {
				if (!repack(false, true)) {
					dataMgr.dataTypeChanged(this, false);
				}
			}
			else {
				updateComposite(-1, structLength + offsetAdjustment, -1, true); // update length only
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
	public DataTypeComponentDB getComponent(int ordinal) {
		lock.acquire();
		try {
			checkIsValid();
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
				if (dtc.getLength() == 0) {
					--offset;
				}
			}
			// return undefined component
			return new DataTypeComponentDB(dataMgr, this, ordinal, offset);
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
				return 1; // positive length required
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
			DataTypeComponentDB previous = components.get(index - 1);
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
		DataTypeComponentDB next = components.get(index);
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
			DataTypeComponentDB next = components.get(index + 1);
			if (!next.containsOffset(offset)) {
				break;
			}
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
			if (offset > structLength) {
				return;
			}

			int index =
				Collections.binarySearch(components, Integer.valueOf(offset),
					OffsetComparator.INSTANCE);

			if (index < 0) {
				if (offset == structLength) {
					return;
				}
				shiftOffsets(-index - 1, -1, -1); // updates timestamp
			}
			else {
				// delete all components containing offset working backward from last such component
				index = advanceToLastComponentContainingOffset(index, offset);
				DataTypeComponentDB dtc = components.get(index);
				while (dtc.containsOffset(offset)) {
					doDeleteWithComponentShift(index, false); // updates timestamp
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
	public void clearAtOffset(int offset) {
		lock.acquire();
		try {
			checkDeleted();
			if (offset < 0) {
				throw new IllegalArgumentException("Offset cannot be negative.");
			}
			if (offset > structLength) {
				return;
			}

			int index =
				Collections.binarySearch(components, Integer.valueOf(offset),
					OffsetComparator.INSTANCE);
			if (index < 0) {
				return;
			}

			// clear all components containing offset working backward from last such component
			index = advanceToLastComponentContainingOffset(index, offset);
			DataTypeComponentDB dtc = components.get(index);
			while (dtc.containsOffset(offset)) {
				doDeleteWithComponentShift(index, true); // updates timestamp
				if (--index < 0) {
					break;
				}
				dtc = components.get(index);
			}

			repack(false, false);
			notifySizeChanged(false);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent getDefinedComponentAtOrAfterOffset(int offset) {
		lock.acquire();
		try {
			checkIsValid();
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
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent getComponentContaining(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset > structLength || offset < 0) {
				return null;
			}
			int index =
				Collections.binarySearch(components, Integer.valueOf(offset),
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
		finally {
			lock.release();
		}
	}
	
	@Override
	public List<DataTypeComponent> getComponentsContaining(int offset) {
		lock.acquire();
		try {
			checkIsValid();
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
				DataTypeComponentDB dtc = components.get(index);
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
		finally {
			lock.release();
		}
	}

	/**
	 * Generate an undefined component following a binary search across the defined components.
	 * @param offset the offset within this structure which was searched for
	 * @param missingComponentIndex the defined component binary search index result (must be negative)
	 * @return undefined component 
	 */
	private DataTypeComponentDB generateUndefinedComponent(int offset, int missingComponentIndex) {
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
		return new DataTypeComponentDB(dataMgr, this, ordinal, offset);
	}

	@Override
	public DataTypeComponent getDataTypeAt(int offset) {
		lock.acquire();
		try {
			DataTypeComponent dtc = getComponentContaining(offset);
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
				numComponents += offset - structLength;
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
				return new DataTypeComponentDB(dataMgr, this, ordinal, offset);
			}

			length = getPreferredComponentLength(dataType, length);

			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, length,
				ordinal, offset, name, comment);
			dataType.addParent(this);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			shiftOffsets(index, 1 + additionalShift, length + additionalShift);
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
	public final DataTypeComponent replace(int ordinal, DataType dataType, int length)
			throws IllegalArgumentException {
		return replace(ordinal, dataType, length, null, null);
	}

	@Override
	public DataTypeComponent replace(int ordinal, DataType dataType, int length,
			String componentName,
			String comment) {
		lock.acquire();
		try {
			checkDeleted();

			if (ordinal < 0 || ordinal >= numComponents) {
				throw new IndexOutOfBoundsException(ordinal);
			}

			dataType = validateDataType(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

			length = getPreferredComponentLength(dataType, length);

			LinkedList<DataTypeComponentDB> replacedComponents = new LinkedList<>();
			int offset;

			int index = ordinal;
			if (!isPackingEnabled()) {
				index = Collections.binarySearch(components, Integer.valueOf(ordinal),
					OrdinalComparator.INSTANCE);
			}
			if (index >= 0) {
				// defined component
				DataTypeComponentDB origDtc = components.get(index);
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
				DataTypeComponentDB origDtc =
					new DataTypeComponentDB(dataMgr, this, ordinal, offset);
				if (dataType == DataType.DEFAULT) {
					return origDtc; // no change
				}
				replacedComponents.add(origDtc);
			}

			DataTypeComponent replaceComponent =
				replaceComponents(replacedComponents, dataType, offset, length, componentName,
					comment);

			repack(false, false);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeAdapter.updateRecord(record, true);
			notifySizeChanged(false);

			return replaceComponent != null ? replaceComponent : getComponent(ordinal);
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
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {
		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		
		lock.acquire();
		try {
			checkDeleted();
			
			if (offset >= structLength) {
				throw new IllegalArgumentException(
					"Offset " + offset + " is beyond end of structure (" + structLength + ").");
			}

			dataType = validateDataType(dataType);
			dataType = resolve(dataType);
			checkAncestry(dataType);

			LinkedList<DataTypeComponentDB> replacedComponents = new LinkedList<>();

			DataTypeComponentDB origDtc = null;
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
					replacedComponents.add(
						new DataTypeComponentDB(dataMgr, this, origDtc.getOrdinal() + 1, offset));
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
				origDtc = new DataTypeComponentDB(dataMgr, this, ordinal, offset);
				if (dataType == DataType.DEFAULT) {
					return origDtc; // no change
				}
				replacedComponents.add(origDtc);
			}

			length = getPreferredComponentLength(dataType, length);

			DataTypeComponent replaceComponent =
				replaceComponents(replacedComponents, dataType, offset, length, name, comment);

			repack(false, false);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeAdapter.updateRecord(record, true);
			notifySizeChanged(false);

			return replaceComponent != null ? replaceComponent : getComponentContaining(offset);
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
		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		DataType[] resolvedDts = new DataType[otherComponents.length];
		for (int i = 0; i < otherComponents.length; i++) {
			resolvedDts[i] = doCheckedResolve(otherComponents[i].getDataType());
		}
		for (DataTypeComponentDB dtc : components) {
			dtc.getDataType().removeParent(this);
			componentAdapter.removeRecord(dtc.getKey());
		}

		components.clear();
		numComponents = 0;
		structLength = 0;
		structAlignment = -1;
		computedAlignment = -1;

		doSetPackingAndAlignment(struct); // updates timestamp

		if (struct.isPackingEnabled()) {
			doReplaceWithPacked(struct, resolvedDts);
		}
		else {
			doReplaceWithNonPacked(struct, resolvedDts);
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

	private void doReplaceWithPacked(Structure struct, DataType[] resolvedDts) {
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

	private void doReplaceWithNonPacked(Structure struct, DataType[] resolvedDts)
			throws IOException {
		// assumes components is clear and that alignment characteristics have been set.
		if (struct.isNotYetDefined()) {
			return;
		}

		structLength = struct.isZeroLength() ? 0 : struct.getLength();
		numComponents = structLength;

		DataTypeComponent[] otherComponents = struct.getDefinedComponents();
		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];

			DataType dt = resolvedDts[i]; // ancestry check already performed by caller
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
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			boolean changed = false;
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
					int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
					if (length < 0) {
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
			if (dt instanceof Dynamic) {
				continue; // length can't change
			}
			if (dt instanceof BitFieldDataType) {
				// TODO: could get messy
				continue;
			}
			int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
			if (length < 0) {
				continue; // illegal condition - skip
			}
			int dtcLen = dtc.getLength();
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

	private int getLastDefinedComponentOrdinal() {
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
	 * @param resolvedDataType the data type of the new component
	 * @param newOffset offset of replacement component which must fall within origComponents bounds
	 * @param length the length of the new component
	 * @param name the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if only a clear operation was performed.
	 * @throws IOException if database IO error occurs
	 * @throws IllegalArgumentException if unable to identify/make sufficient space 
	 */
	private DataTypeComponent replaceComponents(LinkedList<DataTypeComponentDB> origComponents,
			DataType resolvedDataType, int newOffset, int length, String name, String comment)
			throws IOException, IllegalArgumentException {

		boolean clearOnly = false;
		if (resolvedDataType == DataType.DEFAULT) {
			clearOnly = true;
			length = 0; // nothing gets consumed
		}

		DataTypeComponentDB origFirstDtc = origComponents.getFirst();
		DataTypeComponentDB origLastDtc = origComponents.getLast();
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
			for (DataTypeComponentDB origDtc : origComponents) {
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
			checkUndefinedSpaceAvailabilityAfter(origLastOrdinal, bytesNeeded, resolvedDataType,
				newOffset);
		}

		// determine defined component list insertion point, remove old components
		// and insert new component in list
		int index;
		if (isPackingEnabled()) {
			index = newOrdinal;
		}
		else {
			index =
				Collections.binarySearch(components, Integer.valueOf(origFirstOrdinal),
					OrdinalComparator.INSTANCE);
		}
		if (index < 0) {
			index = -index - 1; // undefined component replacement
		}
		else {
			for (DataTypeComponentDB origDtc : origComponents) {
				DataTypeComponentDB dtc = doDelete(index);
				if (dtc != origDtc) {
					throw new AssertException("component replacement mismatch");
				}
			}
		}

		DataTypeComponentDB newDtc = null;
		if (!clearOnly) {
			// insert new component
			DBRecord rec = componentAdapter.createRecord(dataMgr.getResolvedID(resolvedDataType),
				key, length, newOrdinal, newOffset, name, comment);
			resolvedDataType.addParent(this);
			newDtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			components.add(index, newDtc);
		}

		// adjust ordinals of trailing components - defer if packing is enabled
		if (!isPackingEnabled()) {
			int deltaOrdinal = -origComponents.size() + origLength - length;
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
				replacementDt = resolve(replacementDt);
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
				notifySizeChanged(false); // also handles alignment change
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void setComponentDataType(DataTypeComponentDB comp, DataType newDt,
			int nextIndex) {

		int oldLen = comp.getLength();
		int len = DataTypeComponent.usesZeroLengthComponent(newDt) ? 0 : newDt.getLength();
		if (len < 0) {
			len = oldLen;
		}

		comp.getDataType().removeParent(this);

		if (isPackingEnabled()) {
			comp.setLength(len, false); // do before record save below
		}
		comp.setDataType(newDt); // saves component record
		newDt.addParent(this);

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
			else if (comp.getOrdinal() == getLastDefinedComponentOrdinal()) {
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
				changed |= updateComposite(components.size(), packResult.structureLength,
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

	private boolean updateComposite(int currentNumComponents, int currentLength,
			int currentAlignment, boolean setLastChangeTime) {
		boolean compositeChanged = false;
		if (currentNumComponents >= 0 && numComponents != currentNumComponents) {
			numComponents = currentNumComponents;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
			setLastChangeTime = true;
			compositeChanged = true;
		}
		if (currentLength >= 0 && structLength != currentLength) {
			structLength = currentLength;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
			compositeChanged = true;
		}
		if (currentAlignment >= 0 && structAlignment != currentAlignment) {
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

}
