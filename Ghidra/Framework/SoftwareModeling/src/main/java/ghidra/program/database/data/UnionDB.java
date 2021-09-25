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
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;

/**
 * Database implementation for the Union data type.
 */
class UnionDB extends CompositeDB implements UnionInternal {

	private int unionLength;
	private int unionAlignment;  // reflects stored alignment, -1 if not yet stored
	private int computedAlignment = -1; // cached alignment if not yet stored

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
	public UnionDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
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
				components.add(new DataTypeComponentDB(dataMgr, componentAdapter, this, rec));
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
		lock.acquire();
		try {
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
		finally {
			lock.release();
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

	private DataTypeComponent doAdd(DataType dataType, int length, String name, String comment,
			boolean validateAlignAndNotify) throws DataTypeDependencyException {

		dataType = validateDataType(dataType);

		dataType = adjustBitField(dataType);

		if (validateAlignAndNotify) {
			dataType = resolve(dataType);
			checkAncestry(dataType);
		}

		length = getPreferredComponentLength(dataType, length);

		DataTypeComponentDB dtc = createComponent(dataMgr.getResolvedID(dataType), length,
			components.size(), 0, name, comment);
		dataType.addParent(this);

		components.add(dtc);

		return dtc;
	}

	private DataTypeComponentDB createComponent(long dtID, int length, int ordinal, int offset,
			String name, String comment) {
		DBRecord rec;
		try {
			rec = componentAdapter.createRecord(dtID, key, length, ordinal, offset, name, comment);
			return new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return null;
	}

	private void removeComponent(long compKey) {
		try {
			componentAdapter.removeRecord(compKey);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) throws IllegalArgumentException {
		lock.acquire();
		try {
			checkDeleted();
			dataType = validateDataType(dataType);

			dataType = adjustBitField(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

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
		finally {
			lock.release();
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
		lock.acquire();
		try {
			checkDeleted();

			getComputedAlignment(true); // ensure previous alignment has been stored

			DataTypeComponentDB dtc = components.remove(ordinal);
			dtc.getDataType().removeParent(this);
			removeComponent(dtc.getKey());
			shiftOrdinals(ordinal, -1);

			if (!repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void delete(Set<Integer> ordinals) {
		if (ordinals.isEmpty()) {
			return;
		}

		lock.acquire();
		try {
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
					// component removed
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
				unionLength = newLength;
				notifySizeChanged(false);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof UnionInternal)) {
			throw new IllegalArgumentException();
		}
		lock.acquire();
		boolean isResolveCacheOwner = dataMgr.activateResolveCache();
		try {
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
				dataMgr.flushResolveQueue(true);
			}
			lock.release();
		}
	}

	void doReplaceWith(UnionInternal union, boolean notify)
			throws DataTypeDependencyException, IOException {

		// pre-resolved component types to catch dependency issues early
		DataTypeComponent[] otherComponents = union.getComponents();
		DataType[] resolvedDts = new DataType[otherComponents.length];
		for (int i = 0; i < otherComponents.length; i++) {
			resolvedDts[i] = doCheckedResolve(otherComponents[i].getDataType());
			checkAncestry(resolvedDts[i]);
		}

		for (DataTypeComponentDB dtc : components) {
			dtc.getDataType().removeParent(this);
			removeComponent(dtc.getKey());
		}
		components.clear();
		unionAlignment = -1;
		computedAlignment = -1;

		doSetPackingAndAlignment(union);

		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			doAdd(resolvedDts[i], dtc.getLength(), dtc.getFieldName(), dtc.getComment(), false);
		}

		repack(false, false);

		if (notify) {
			notifySizeChanged(false); // assume size and/or alignment changed
		}

		if (pointerPostResolveRequired) {
			dataMgr.queuePostResolve(this, union);
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
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumComponents() {
		lock.acquire();
		try {
			checkIsValid();
			return components.size();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumDefinedComponents() {
		return getNumComponents();
	}

	@Override
	public DataTypeComponent getComponent(int ordinal) {
		lock.acquire();
		try {
			checkIsValid();
			if (ordinal < 0 || ordinal >= components.size()) {
				return null;
			}
			return components.get(ordinal);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponentDB[] getComponents() {
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
	public DataTypeComponentDB[] getDefinedComponents() {
		return getComponents();
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
		lock.acquire();
		try {
			checkIsValid();
			if (unionLength == 0) {
				return 1; // positive length required
			}
			return unionLength;
		}
		finally {
			lock.release();
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
			int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
			if (length < 0) {
				continue; // illegal condition - skip
			}
			if (length != dtc.getLength()) {
				dtc.setLength(length, true);
				changed = true;
			}
		}
		if (changed) {
			// NOTE: since we do not retain our external alignment we have no way of knowing if
			// it has changed, so we must assume it has if we are an aligned union
			// Do not notify parents
			if (!repack(false, false)) {
				dataMgr.dataTypeChanged(this, false);
			}
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		if (!isPackingEnabled()) {
			return;
		}
		if (dt instanceof BitFieldDataType) {
			return; // unsupported
		}
		lock.acquire();
		try {
			checkDeleted();
			repack(true, true);
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
			boolean changed = false;
			for (DataTypeComponentDB dtc : components) {
				if (dtc.getDataType() == dt) {
					int length = DataTypeComponent.usesZeroLengthComponent(dt) ? 0 : dt.getLength();
					if (length >= 0 && length != dtc.getLength()) {
						dtc.setLength(length, true);
						changed = true;
					}
				}
			}
			if (changed && !repack(true, true)) {
				dataMgr.dataTypeChanged(this, true);
			}
		}
		finally {
			lock.release();
		}
	}

	private DataType adjustBitField(DataType dataType) {

		if (!(dataType instanceof BitFieldDataType)) {
			return dataType;
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) dataType;

		DataType baseDataType = bitfieldDt.getBaseDataType();
		baseDataType = resolve(baseDataType);

		// Both aligned and non-packed bitfields use same adjustment
		// non-packed must force bitfield placement at byte offset 0
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
		lock.acquire();
		try {
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
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			boolean changed = false;
			for (int i = components.size() - 1; i >= 0; i--) { // reverse order
				DataTypeComponentDB dtc = components.get(i);
				boolean removeBitFieldComponent = false;
				if (dtc.isBitFieldComponent()) {
					BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
					removeBitFieldComponent = bitfieldDt.getBaseDataType() == dt;
				}
				if (removeBitFieldComponent || dtc.getDataType() == dt) {
					dt.removeParent(this);
					components.remove(i);
					removeComponent(dtc.getKey());
					shiftOrdinals(i, -1);
					changed = true;
				}
			}
			if (changed && !repack(false, true)) {
				dataMgr.dataTypeChanged(this, false);
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
		if (!(dataType instanceof UnionInternal)) {
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
			UnionInternal union = (UnionInternal) dataType;
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
			for (int i = 0; i < myComps.length; i++) {
				if (!myComps[i].isEquivalent(otherComps[i])) {
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

	private void shiftOrdinals(int ordinal, int deltaOrdinal) {
		for (int i = ordinal; i < components.size(); i++) {
			DataTypeComponentDB dtc = components.get(i);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal, true);
		}
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
					(replacementDt.getDataTypeManager() != getDataTypeManager())) {
					replacementDt = resolve(replacementDt);
				}
				checkAncestry(replacementDt);
			}
			catch (Exception e) {
				// TODO: should we use Undefined instead since we do not support
				// DEFAULT in Unions
				replacementDt = DataType.DEFAULT;
			}
			boolean changed = false;
			for (int i = components.size() - 1; i >= 0; i--) {

				DataTypeComponentDB dtc = components.get(i);

				boolean remove = false;
				if (dtc.isBitFieldComponent()) {
					try {
						changed |= updateBitFieldDataType(dtc, oldDt, replacementDt);
					}
					catch (InvalidDataTypeException e) {
						Msg.error(this,
							"Invalid bitfield replacement type " + newDt.getName() +
								", removing bitfield " + dtc.getDataType().getName() + ": " +
								getPathName());
						remove = true;
					}
				}
				else if (dtc.getDataType() == oldDt) {
					if (replacementDt == DEFAULT) {
						Msg.error(this,
							"Invalid replacement type " + newDt.getName() +
								", removing component " + dtc.getDataType().getName() + ": " +
								getPathName());
						remove = true;
					}
					else {
						int len = DataTypeComponent.usesZeroLengthComponent(newDt) ? 0
								: newDt.getLength();
						if (len < 0) {
							len = dtc.getLength();
						}
						oldDt.removeParent(this);
						dtc.setLength(len, false);
						dtc.setDataType(replacementDt); // updates record
						replacementDt.addParent(this);
						changed = true;
					}
				}
				if (remove) {
					oldDt.removeParent(this);
					components.remove(i);
					removeComponent(dtc.getKey());
					shiftOrdinals(i, -1);
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

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// ignored
	}

	@Override
	public boolean dependsOn(DataType dt) {
		lock.acquire();
		try {
			checkIsValid();
			if (getNumComponents() == 1) {
				DataTypeComponent dtc = getComponent(0);
				return dtc.getDataType().dependsOn(dt);
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UNION_" + getName();
	}

}
