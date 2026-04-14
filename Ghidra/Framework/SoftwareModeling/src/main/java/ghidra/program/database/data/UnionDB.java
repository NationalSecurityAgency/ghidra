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
import java.util.function.Consumer;

import db.DBRecord;
import db.Field;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Lock.Closeable;

/**
 * Database implementation for the Union data type.
 */
class UnionDB extends CompositeDB implements UnionInternal {

	private int unionLength;
	private int unionAlignment;  // reflects stored alignment, -1 if not yet stored
	private int computedAlignment = -1; // lazy, cached alignment, -1 if not yet computed

	private List<DataTypeComponentDB> components;

	/**
	 * Constructor
	 * @param dataMgr the datatypes manager
	 * @param compositeAdapter the composites database adapter
	 * @param componentAdapter the components database adapter
	 * @param record the record for the union
	 */
	UnionDB(DataTypeManagerDB dataMgr, CompositeDBAdapter compositeAdapter,
			ComponentDBAdapter componentAdapter, DBRecord record) {
		super(dataMgr, compositeAdapter, componentAdapter, record);
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
				components.add(component);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		Collections.sort(components, ComponentComparator.INSTANCE);
		unionLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);
		unionAlignment = record.getIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL);
		computedAlignment = -1;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Union>";
		}
		return "";
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) throws IllegalArgumentException {
		try (Closeable c = lock.write()) {
			checkDeleted();
			getComputedAlignment(true); // ensure previous alignment has been stored
			DataTypeComponent dtc = doAdd(dataType, length, componentName, comment, true);
			if (!repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
			}
			return dtc;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	private int getBitFieldAllocation(BitFieldDataType bitfieldDt) {

		BitFieldPacking bitFieldPacking = getDataOrganization().getBitFieldPacking();
		if (bitFieldPacking.useMSConvention()) {
			return bitfieldDt.getBaseTypeSize();
		}

		if (bitfieldDt.getBitSize() == 0) {
			return 0;
		}

		int length = bitfieldDt.getBaseTypeSize();
		int packValue = getStoredPackingValue();
		if (packValue > 0 && length > packValue) {
			length =
				DataOrganizationImpl.getLeastCommonMultiple(bitfieldDt.getStorageSize(), packValue);
		}
		return length;
	}

	private DataTypeComponent doAdd(DataType dataType, int length, String name,
			String comment, boolean validateAlignAndNotify) throws DataTypeDependencyException {

		dataType = validateDataType(dataType);

		dataType = adjustBitField(dataType);

		if (validateAlignAndNotify) {
			dataType = resolve(dataType);
			DataTypeUtilities.checkAncestry(this, dataType);
		}

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentDB dtc = createComponent(dataMgr.getResolvedID(dataType), length,
			components.size(), 0, name, comment);
		dataType.addParent(this);

		components.add(dtc);

		return dtc;
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {
		try (Closeable c = lock.write()) {
			checkDeleted();
			dataType = validateDataType(dataType);

			dataType = adjustBitField(dataType);

			dataType = resolve(dataType);
			DataTypeUtilities.checkAncestry(this, dataType);

			getComputedAlignment(true); // ensure previous alignment has been stored

			length = getPreferredComponentLength(dataType, length);

			DataTypeComponentDB dtc =
				createComponent(dataMgr.getResolvedID(dataType), length, ordinal, 0, name, comment);
			dataType.addParent(this);
			shiftOrdinals(ordinal, 1);
			components.add(ordinal, dtc);

			if (!repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
			}
			return dtc;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	@Override
	public DataTypeComponent addBitField(DataType baseDataType, int bitSize, String componentName,
			String comment) throws InvalidDataTypeException {
		return insertBitField(components.size(), baseDataType, bitSize, componentName, comment);
	}

	@Override
	public DataTypeComponent insertBitField(int ordinal, DataType baseDataType, int bitSize,
			String componentName, String comment)
			throws InvalidDataTypeException, IndexOutOfBoundsException {

		if (ordinal < 0 || ordinal > components.size()) {
			throw new IndexOutOfBoundsException(ordinal);
		}

		BitFieldDataType bitFieldDt = new BitFieldDBDataType(baseDataType, bitSize, 0);
		return insert(ordinal, bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
	}

	@Override
	public void delete(int ordinal) {
		try (Closeable c = lock.write()) {
			checkDeleted();

			getComputedAlignment(true); // ensure previous alignment has been stored

			DataTypeComponentDB dtc = components.remove(ordinal);
			doDelete(dtc);

			shiftOrdinals(ordinal, -1);

			if (!repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void delete(Set<Integer> ordinals) {

		if (ordinals.isEmpty()) {
			return;
		}

		if (ordinals.size() == 1) {
			ordinals.forEach(ordinal -> delete(ordinal));
			return;
		}

		try (Closeable c = lock.write()) {
			checkDeleted();

			if (isPackingEnabled()) {
				getComputedAlignment(true); // ensure previous alignment has been stored
			}

			List<DataTypeComponentDB> newComponents = new ArrayList<>();
			int newLength = 0;
			int ordinalAdjustment = 0;
			for (DataTypeComponentDB dtc : components) {
				int ordinal = dtc.getOrdinal();
				if (ordinals.contains(ordinal)) {
					// component removed - delete record
					doDelete(dtc);
					--ordinalAdjustment;
				}
				else {
					if (ordinalAdjustment != 0) {
						dtc.setOrdinal(dtc.getOrdinal() + ordinalAdjustment, true);
					}
					newComponents.add(dtc);
					newLength = Math.max(newLength, dtc.getLength());
				}
			}
			components = newComponents;

			if (isPackingEnabled()) {
				if (!repack(false, true)) {
					dataMgr.dataTypeChanged(this, false);
				}
			}
			else {
				boolean sizeChanged = (unionLength != newLength);
				if (sizeChanged) {
					unionLength = newLength;
					record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, unionLength);
				}
				compositeAdapter.updateRecord(record, true);

				if (sizeChanged) {
					notifySizeChanged(false);
				}
				else {
					dataMgr.dataTypeChanged(this, false);
				}
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof UnionInternal)) {
			throw new IllegalArgumentException();
		}
		boolean isResolveCacheOwner = false;
		try (Closeable c = lock.write()) {
			isResolveCacheOwner = dataMgr.activateResolveCache();
			checkDeleted();
			doReplaceWith((UnionInternal) dataType, true);
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			if (isResolveCacheOwner) {
				dataMgr.processResolveQueue(true);
			}
		}
	}

	void doReplaceWith(UnionInternal union, boolean notify)
			throws DataTypeDependencyException, IOException {

		int oldAlignment = getAlignment();
		int oldLength = unionLength;

		// pre-resolved component types to catch dependency issues early
		DataTypeComponent[] otherComponents = union.getComponents();
		DataType[] resolvedDts = new DataType[otherComponents.length];
		for (int i = 0; i < otherComponents.length; i++) {
			resolvedDts[i] = doCheckedResolve(otherComponents[i].getDataType());
		}

		for (DataTypeComponentDB dtc : components) {
			doDelete(dtc);
		}

		components.clear();
		unionAlignment = -1;
		computedAlignment = -1;

		doSetPackingAndAlignment(union);

		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			doAdd(resolvedDts[i], dtc.getLength(), dtc.getFieldName(), dtc.getComment(),
				false);
		}

		repack(false, false);

		record.setString(CompositeDBAdapter.COMPOSITE_COMMENT_COL, union.getDescription());
		compositeAdapter.updateRecord(record, true); // updates timestamp

		if (notify) {
			if (unionLength != oldLength) {
				notifySizeChanged(false);
			}
			else if (unionAlignment != oldAlignment) {
				notifyAlignmentChanged(false);
			}
			else {
				dataMgr.dataTypeChanged(this, false);
			}
		}

		if (pointerPostResolveRequired) {
			dataMgr.queuePostResolve(this, union);
		}
	}

	@Override
	public boolean isPartOf(DataType dataType) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (equals(dataType)) {
				return true;
			}
			for (DataTypeComponent dtc : components) {
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
	}

	@Override
	public int getNumComponents() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return components.size();
		}
	}

	@Override
	public int getNumDefinedComponents() {
		return getNumComponents();
	}

	@Override
	public DataTypeComponentDB getComponent(int ordinal) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (ordinal < 0 || ordinal >= components.size()) {
				return null;
			}
			return components.get(ordinal);
		}
	}

	@Override
	public DataTypeComponentDB[] getComponents() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return components.toArray(new DataTypeComponentDB[components.size()]);
		}
	}

	@Override
	public DataTypeComponentDB[] getDefinedComponents() {
		return getComponents();
	}

	@Override
	void forEachDefinedComponent(Consumer<DataTypeComponentDB> dtcConsumer) {
		components.forEach(dtcConsumer);
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		UnionDataType union = new UnionDataType(getCategoryPath(), getName(), dtm);
		union.setDescription(getDescription());
		union.replaceWith(this);
		return union;
	}

	@Override
	public Union clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		UnionDataType union = new UnionDataType(getCategoryPath(), getName(), getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		union.setDescription(getDescription());
		union.replaceWith(this);
		return union;
	}

	@Override
	public boolean isZeroLength() {
		return unionLength == 0;
	}

	@Override
	public int getLength() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (unionLength == 0) {
				return 1; // positive length required
			}
			return unionLength;
		}
	}

	@Override
	public boolean hasLanguageDependantLength() {
		// Assume any component may have a language-dependent length
		return true;
	}

	@Override
	protected void fixupComponents() {
		boolean changed = false;
		for (DataTypeComponentDB dtc : components) {
			DataType dt = dtc.getDataType();
			if (dt instanceof Dynamic) {
				continue; // length can't change
			}
			if (dt instanceof BitFieldDataType) {
				dt = adjustBitField(dt); // in case base type changed
			}
			int length = getPreferredComponentLength(dt, -1);
			if (length < 0) {
				continue; // illegal condition - skip
			}
			if (length != dtc.getLength()) {
				dtc.setLength(length, true);
				changed = true;
			}
		}
		if (changed) {
			// Do not notify parents - must be invoked in composite dependency order
			// Treat as an auto-change as a result of data organization change
			repack(true, false);
			dataMgr.dataTypeChanged(this, true);
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (deleting) {
			return;
		}
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		try (Closeable c = lock.write()) {
			checkDeleted();
			if (isPackingEnabled()) {
				repack(true, true);
			}
		}
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		if (deleting) {
			return;
		}
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		try (Closeable c = lock.write()) {
			checkDeleted();
			boolean changed = false;
			for (DataTypeComponentDB dtc : components) {
				if (dtc.getDataType() == dt) {
					int length = getPreferredComponentLength(dt, dtc.getLength());
					if (length != dtc.getLength()) {
						dtc.setLength(length, true);
						changed = true;
					}
				}
			}
			if (changed && !repack(true, true)) {
				dataMgr.dataTypeChanged(this, true);
			}
		}
	}

	private DataType adjustBitField(DataType dataType) {

		if (!(dataType instanceof BitFieldDataType)) {
			return dataType;
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) dataType;

		DataType baseDataType = bitfieldDt.getBaseDataType();
		baseDataType = resolve(baseDataType);

		// Both packed and non-packed bitfields use same adjustment
		// Non-packed must force bitfield placement at byte offset 0
		int bitSize = bitfieldDt.getDeclaredBitSize();
		int effectiveBitSize =
			BitFieldDataType.getEffectiveBitSize(bitSize, baseDataType.getLength());

		// little-endian always uses bit offset of 0 while
		// big-endian offset must be computed
		boolean bigEndian = getDataOrganization().isBigEndian();
		int storageBitOffset = 0;
		if (bigEndian) {
			if (bitSize == 0) {
				storageBitOffset = 7;
			}
			else {
				int storageSize = BitFieldDataType.getMinimumStorageSize(effectiveBitSize);
				storageBitOffset = (8 * storageSize) - effectiveBitSize;
			}
		}

		if (effectiveBitSize != bitfieldDt.getBitSize() ||
			storageBitOffset != bitfieldDt.getBitOffset()) {
			try {
				bitfieldDt =
					new BitFieldDBDataType(baseDataType, effectiveBitSize, storageBitOffset);
			}
			catch (InvalidDataTypeException e) {
				// unexpected since deriving from existing bitfield,
				// ignore and use existing bitfield
			}
		}
		return bitfieldDt;
	}

	@Override
	protected int getComputedAlignment(boolean updateRecord) {
		if (unionAlignment > 0) {
			return unionAlignment;
		}
		if (computedAlignment <= 0) {
			if (isPackingEnabled()) {
				computedAlignment =
					CompositeAlignmentHelper.getAlignment(getDataOrganization(), this);
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
			unionAlignment = computedAlignment;
			computedAlignment = -1;
			return unionAlignment;
		}
		return computedAlignment;
	}

	/**
	 * Perform union member repack.
	 * Perform lazy update of stored alignment introduced with v5 adapter.
	 */
	@Override
	protected boolean repack(boolean isAutoChange, boolean notify) {
		try (Closeable c = lock.write()) {
			checkDeleted();

			int oldLength = unionLength;
			boolean storeAlignment = (unionAlignment <= 0); // lazy upgrade for v5 adapter
			int oldAlignment = getComputedAlignment(false);

			unionLength = 0;
			for (DataTypeComponent dtc : components) {
				// TODO: compute alignment in this loop
				int length = dtc.getLength();
				if (isPackingEnabled() && dtc.isBitFieldComponent()) {
					// revise length to reflect compiler bitfield allocation rules
					length = getBitFieldAllocation((BitFieldDataType) dtc.getDataType());
				}
				unionLength = Math.max(length, unionLength);
			}

			computedAlignment = -1; // force recompute of unionAlignment
			unionAlignment = -1;
			unionAlignment = getComputedAlignment(false);

			if (isPackingEnabled()) {
				unionLength = DataOrganizationImpl.getAlignedOffset(unionAlignment, unionLength);
			}

			boolean changed = (oldLength != unionLength) || (oldAlignment != unionAlignment);

			if (changed || storeAlignment) {
				record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, unionLength);
				record.setIntValue(CompositeDBAdapter.COMPOSITE_ALIGNMENT_COL, unionAlignment);
				try {
					compositeAdapter.updateRecord(record, changed && !isAutoChange);
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
			}

			if (changed & notify) {
				if (oldLength != unionLength) {
					notifySizeChanged(isAutoChange);
				}
				else if (oldAlignment != unionAlignment) {
					notifyAlignmentChanged(isAutoChange);
				}
				else {
					dataMgr.dataTypeChanged(this, isAutoChange);
				}
			}
			return changed;
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		if (deleting) {
			return;
		}
		try (Closeable c = lock.write()) {
			checkDeleted();
			boolean changed = false;
			for (int i = components.size() - 1; i >= 0; i--) { // reverse order
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.isBitFieldComponent()) {

					// Do not allow bitfield to be destroyed
					// If base type is removed - revert to primitive type
					BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
					if (bitfieldDt.getBaseDataType() == dt) {
						AbstractIntegerDataType primitiveDt = bitfieldDt.getPrimitiveBaseDataType();
						dataMgr.blockDataTypeRemoval(primitiveDt);
						if (primitiveDt != dt && updateBitFieldDataType(dtc, dt, primitiveDt)) {
							dtc.setComment(
								prependComment("Type '" + dt.getDisplayName() + "' was deleted",
									dtc.getComment()));
							changed = true;
						}
					}
				}
				else if (dtc.getDataType() == dt) {
					dt.removeParent(this);
					dtc.setDataType(BadDataType.dataType); // updates record
					dataMgr.getSettingsAdapter().removeAllSettingsRecords(dtc.getKey());
					dtc.setComment(prependComment("Type '" + dt.getDisplayName() + "' was deleted",
						dtc.getComment()));
					changed = true;
				}
			}
			if (changed && (!isPackingEnabled() || !repack(false, true))) {
				dataMgr.dataTypeChanged(this, false);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	protected boolean isEquivalent(DataType dataType, DataTypeConflictHandler handler) {
		if (dataType == this) {
			return true;
		}
		if (!(dataType instanceof UnionInternal union)) {
			return false;
		}

		validate(lock);
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

			if (handler != null &&
				ConflictResult.USE_EXISTING == handler.resolveConflict(union, this)) {
				// treat this type as equivalent if existing type will be used
				isEquivalent = true;
				return true;
			}

			if (getStoredPackingValue() != union.getStoredPackingValue() ||
				getStoredMinimumAlignment() != union.getStoredMinimumAlignment()) {
				// rely on component match instead of checking length 
				// since dynamic component sizes could affect length
				return false;
			}
			DataTypeComponent[] myComps = getComponents();
			DataTypeComponent[] otherComps = union.getComponents();
			if (myComps.length != otherComps.length) {
				return false;
			}
			if (handler != null) {
				handler = handler.getSubsequentHandler();
			}
			for (int i = 0; i < myComps.length; i++) {
				if (!DataTypeComponentDB.isEquivalent(myComps[i], otherComps[i], handler)) {
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

	@Override
	public boolean isEquivalent(DataType dt) {
		return isEquivalent(dt, null);
	}

	private void shiftOrdinals(int ordinal, int deltaOrdinal) {
		for (int i = ordinal; i < components.size(); i++) {
			DataTypeComponentDB dtc = components.get(i);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal, true);
		}
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (deleting) {
			return;
		}
		DataTypeUtilities.checkValidReplacement(oldDt, newDt);
		try (Closeable c = lock.write()) {
			checkDeleted();
			DataType replacementDt = newDt;
			try {
				replacementDt = validateDataType(replacementDt); // blocks DEFAULT use
				replacementDt = replacementDt.clone(dataMgr);
				DataTypeUtilities.checkAncestry(this, replacementDt);
			}
			catch (Exception e) {
				replacementDt = Undefined1DataType.dataType;
			}
			boolean changed = false;
			for (int i = components.size() - 1; i >= 0; i--) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.isBitFieldComponent()) {
					changed |= updateBitFieldDataType(dtc, oldDt, replacementDt);
				}
				else if (dtc.getDataType() == oldDt) {
					int len = getPreferredComponentLength(newDt, dtc.getLength());
					dtc.setLength(len, false);
					oldDt.removeParent(this);
					dtc.setDataType(replacementDt); // updates record
					dataMgr.getSettingsAdapter().removeAllSettingsRecords(dtc.getKey());
					replacementDt.addParent(this);
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
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignored
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UNION_" + getName();
	}

}
