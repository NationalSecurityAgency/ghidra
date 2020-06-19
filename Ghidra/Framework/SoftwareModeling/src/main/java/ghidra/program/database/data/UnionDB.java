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

import db.Record;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;

/**
 * Database implementation for the Union data type.
 */
class UnionDB extends CompositeDB implements Union {

	private ArrayList<DataTypeComponentDB> components;
	private int unionLength;
	private static MemberComparator comparator = new MemberComparator();

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
			Record record) {
		super(dataMgr, cache, compositeAdapter, componentAdapter, record);
	}

	@Override
	protected void initialize() {

		components = new ArrayList<>();

		try {
			long[] ids = componentAdapter.getComponentIdsInComposite(key);
			for (long id : ids) {
				Record rec = componentAdapter.getRecord(id);
				components.add(new DataTypeComponentDB(dataMgr, componentAdapter, this, rec));
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		Collections.sort(components, comparator);
		unionLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);

	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Union>";
		}
		return "";
	}

	@Override
	public boolean isNotYetDefined() {
		return components.size() == 0;
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String componentName,
			String comment) throws IllegalArgumentException {
		lock.acquire();
		try {
			checkDeleted();
			DataTypeComponent dtc = doAdd(dataType, length, componentName, comment, true);
			adjustLength(true, true);
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

		BitFieldPacking bitFieldPacking = getBitFieldPacking();
		if (bitFieldPacking.useMSConvention()) {
			return bitfieldDt.getBaseTypeSize();
		}

		if (bitfieldDt.getBitSize() == 0) {
			return 0;
		}

		int length = bitfieldDt.getBaseTypeSize();
		int packValue = getPackingValue();
		if (packValue != NOT_PACKING && length > packValue) {
			length =
				DataOrganizationImpl.getLeastCommonMultiple(bitfieldDt.getStorageSize(), packValue);
		}
		return length;
	}

	private DataTypeComponent doAdd(DataType dataType, int length, String name, String comment,
			boolean validateAlignAndNotify) throws DataTypeDependencyException {

		validateDataType(dataType);

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
		Record rec;
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
			validateDataType(dataType);

			dataType = adjustBitField(dataType);

			dataType = resolve(dataType);
			checkAncestry(dataType);

			length = getPreferredComponentLength(dataType, length);

			DataTypeComponentDB dtc =
				createComponent(dataMgr.getResolvedID(dataType), length, ordinal, 0, name, comment);
			dataType.addParent(this);
			shiftOrdinals(ordinal, 1);
			components.add(ordinal, dtc);

			adjustLength(true, true);
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
			throws InvalidDataTypeException, ArrayIndexOutOfBoundsException {

		if (ordinal < 0 || ordinal > components.size()) {
			throw new ArrayIndexOutOfBoundsException(ordinal);
		}

		BitFieldDataType bitFieldDt = new BitFieldDBDataType(baseDataType, bitSize, 0);
		return insert(ordinal, bitFieldDt, bitFieldDt.getStorageSize(), componentName, comment);
	}

	@Override
	public void delete(int ordinal) {
		lock.acquire();
		try {
			checkDeleted();

			DataTypeComponentDB dtc = components.remove(ordinal);
			dtc.getDataType().removeParent(this);
			removeComponent(dtc.getKey());
			shiftOrdinals(ordinal, -1);

			adjustLength(true, true);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void delete(int[] ordinals) {
		for (int ordinal : ordinals) {
			delete(ordinal);
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Union)) {
			throw new IllegalArgumentException();
		}
		lock.acquire();
		boolean isResolveCacheOwner = dataMgr.activateResolveCache();
		try {
			checkDeleted();
			doReplaceWith((Union) dataType, true);
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		finally {
			if (isResolveCacheOwner) {
				dataMgr.flushResolveQueue(true);
			}
			lock.release();
		}
	}

	void doReplaceWith(Union union, boolean notify)
			throws DataTypeDependencyException {

		// pre-resolved component types to catch dependency issues early
		DataTypeComponent[] otherComponents = union.getComponents();
		DataType[] resolvedDts = new DataType[otherComponents.length];
		for (int i = 0; i < otherComponents.length; i++) {
			resolvedDts[i] = doCheckedResolve(otherComponents[i].getDataType());
			checkAncestry(resolvedDts[i]);
		}

		int oldLength = unionLength;
		int oldMinAlignment = getMinimumAlignment();

		for (int i = 0; i < components.size(); i++) {
			DataTypeComponentDB dtc = components.get(i);
			dtc.getDataType().removeParent(this);
			removeComponent(dtc.getKey());
		}
		components.clear();

		setAlignment(union, false);

		for (int i = 0; i < otherComponents.length; i++) {
			DataTypeComponent dtc = otherComponents[i];
			doAdd(resolvedDts[i], dtc.getLength(), dtc.getFieldName(), dtc.getComment(), false);
		}

		adjustLength(false, false);

		if (notify) {
			if (oldMinAlignment != getMinimumAlignment()) {
				notifyAlignmentChanged();
			}
			else if (oldLength != unionLength) {
				notifySizeChanged();
			}
			else {
				dataMgr.dataTypeChanged(this);
			}
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
	public DataType clone(DataTypeManager dtm) {
		UnionDataType union = new UnionDataType(getCategoryPath(), getName(), getUniversalID(),
			getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		union.setDescription(getDescription());
		union.replaceWith(this);
		return union;
	}

	@Override
	public int getLength() {
		lock.acquire();
		try {
			checkIsValid();
			if (unionLength == 0) {
				return 1; // lie about our length
			}
			return unionLength;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			boolean changed = false;
			for (DataTypeComponentDB dtc : components) {
				int length = dtc.getLength();
				if (dtc.getDataType() == dt) {
					length = getPreferredComponentLength(dt, length);
					dtc.setLength(length, true);
					changed = true;
				}
			}
			if (changed) {
				adjustLength(true, false);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		adjustInternalAlignment(true);
	}

	private DataType adjustBitField(DataType dataType) {

		if (!(dataType instanceof BitFieldDataType)) {
			return dataType;
		}

		BitFieldDataType bitfieldDt = (BitFieldDataType) dataType;

		DataType baseDataType = bitfieldDt.getBaseDataType();
		baseDataType = resolve(baseDataType);

		// Both aligned and unaligned bitfields use same adjustment
		// unaligned must force bitfield placement at byte offset 0
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

	private void adjustLength(boolean notify, boolean setLastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = unionLength;

			unionLength = 0;
			for (DataTypeComponent dtc : components) {

				int length = dtc.getLength();
				if (isInternallyAligned() && dtc.isBitFieldComponent()) {
					// revise length to reflect compiler bitfield allocation rules
					length = getBitFieldAllocation((BitFieldDataType) dtc.getDataType());
				}

				unionLength = Math.max(length, unionLength);
			}

			DataOrganization dataOrganization = getDataOrganization();
			int alignment = dataOrganization.getAlignment(this, unionLength);
			int amountFilled = unionLength % alignment;
			if (amountFilled > 0) {
				unionLength += alignment - amountFilled;
			}

			updateLength(oldLength, notify, setLastChangeTime);
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
			boolean didChange = false;
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
					didChange = true;
				}
			}
			if (didChange) {
				adjustLength(true, true);
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
		if (!(dataType instanceof Union)) {
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
			Union union = (Union) dataType;
			if (isInternallyAligned() != union.isInternallyAligned() ||
				isDefaultAligned() != union.isDefaultAligned() ||
				isMachineAligned() != union.isMachineAligned() ||
				getMinimumAlignment() != union.getMinimumAlignment() ||
				getPackingValue() != union.getPackingValue()) {
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

	private void updateLength(int oldLength, boolean notify, boolean setLastChangeTime) {
		if (oldLength != unionLength) {
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, unionLength);
			try {
				compositeAdapter.updateRecord(record, setLastChangeTime);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
			notifySizeChanged();
		}
		else if (notify) {
			dataMgr.dataTypeChanged(this);
		}
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
						oldDt.removeParent(this);
						dtc.setDataType(replacementDt);
						replacementDt.addParent(this);
						int len = replacementDt.getLength();
						if (len > 0) {
							dtc.setLength(len, true);
						}
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
				adjustLength(true, true);
			}
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

	private static class MemberComparator implements Comparator<DataTypeComponent> {
		@Override
		public int compare(DataTypeComponent dtc1, DataTypeComponent dtc2) {
			return dtc1.getOrdinal() - dtc2.getOrdinal();
		}
	}

	@Override
	public String getDefaultLabelPrefix() {
		return "UNION_" + getName();
	}

	@Override
	public void realign() {
		if (isInternallyAligned()) {
			adjustInternalAlignment(true);
		}
	}

	@Override
	public void adjustInternalAlignment(boolean notify) {
		adjustLength(notify, false);
	}
}
