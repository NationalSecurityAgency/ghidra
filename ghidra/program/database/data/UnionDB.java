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

/**
 * Database implementation for the Union data type.
 *
 *
 */
class UnionDB extends CompositeDB implements Union {

	private ArrayList<DataTypeComponentDB> components;
	private int unionLength;
	private static MemberComparator comparator = new MemberComparator();

	/**
	 * Constructor
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
			for (int i = 0; i < ids.length; i++) {
				Record rec = componentAdapter.getRecord(ids[i]);
				components.add(new DataTypeComponentDB(dataMgr, componentAdapter, this, rec));
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		Collections.sort(components, comparator);
		unionLength = record.getIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL);

	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.util.settings.Settings, int)
	 */
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

	/**
	 * @see ghidra.program.model.data.EditableComposite#add(ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent add(DataType dataType, int length, String name, String comment) {
		lock.acquire();
		try {
			checkDeleted();
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			validateDataType(dataType);
			dataType = resolve(dataType);
			checkAncestry(dataType);
			int oldLength = unionLength;
			DataTypeComponent dtc = doAdd(dataType, length, name, comment);
			adjustInternalAlignment(false);
			updateLength(oldLength, true, true);
			return dtc;
		}
		finally {
			lock.release();
		}
	}

	private DataTypeComponent doAdd(DataType resolvedDataType, int length, String name,
			String comment) {

		// TODO Is this the right place to adjust the length?
		int dtLength = resolvedDataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		DataTypeComponentDB dtc = createComponent(dataMgr.getResolvedID(resolvedDataType), length,
			components.size(), 0, name, comment);
		resolvedDataType.addParent(this);

		components.add(dtc);
		unionLength = Math.max(unionLength, length);
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

	/**
	 * @see ghidra.program.model.data.EditableComposite#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent insert(int ordinal, DataType dataType, int length, String name,
			String comment) {
		lock.acquire();
		try {
			checkDeleted();
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			validateDataType(dataType);
			dataType = resolve(dataType);
			checkAncestry(dataType);

			// TODO Is this the right place to adjust the length?
			int dtLength = dataType.getLength();
			if (dtLength > 0 && dtLength < length) {
				length = dtLength;
			}

			int oldLength = unionLength;
			DataTypeComponentDB dtc =
				createComponent(dataMgr.getResolvedID(dataType), length, ordinal, 0, name, comment);
			dataType.addParent(this);
			shiftOrdinals(ordinal, 1);
			components.add(ordinal, dtc);
//			unionLength = Math.max(unionLength, length);
			adjustInternalAlignment(true);
			updateLength(oldLength, true, true);
			return dtc;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.EditableComposite#delete(int)
	 */
	@Override
	public void delete(int ordinal) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = unionLength;
			DataTypeComponentDB dtc = components.remove(ordinal);
			dtc.getDataType().removeParent(this);
			removeComponent(dtc.getKey());
			shiftOrdinals(ordinal, -1);
//			unionLength = computeUnpaddedUnionLength();
			adjustInternalAlignment(false);
			updateLength(oldLength, true, true);
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

	/**
	 * Replaces the internal components of this union with components of the
	 * given union.
	 * @param dataType the union to get the component information from.
	 * @throws IllegalArgumentException if any of the component data types
	 * are not allowed to replace a component in this composite data type.
	 * For example, suppose dt1 contains dt2. Therefore it is not valid
	 * to replace a dt2 component with dt1 since this would cause a cyclic
	 * dependency.
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Union)) {
			throw new IllegalArgumentException();
		}
		doReplaceWith((Union) dataType, true);
	}

	void doReplaceWith(Union union, boolean notify) {
		doReplaceWith(union, notify, null);
	}

	void doReplaceWith(Union union, boolean notify, DataTypeConflictHandler handler) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = unionLength;
			long oldMinAlignment = getMinimumAlignment();
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponentDB dtc = components.get(i);
				dtc.getDataType().removeParent(this);
				removeComponent(dtc.getKey());
			}
			components.clear();

			DataTypeComponent[] otherComponents = union.getComponents();
			for (int i = 0; i < otherComponents.length; i++) {
				DataTypeComponent dtc = otherComponents[i];
				DataType dt = dtc.getDataType();
				dt = resolve(dt, handler);
				checkAncestry(dt);
				int dtLength = dt.getLength();
				if (dtLength <= 0) {
					dtLength = dtc.getLength();
				}
				doAdd(dt, dtLength, dtc.getFieldName(), dtc.getComment());
			}
			setDescription(union.getDescription());
			setAlignment(union, notify);
			updateLength(oldLength, notify, true);
			if (notify && (oldMinAlignment != getMinimumAlignment())) {
				notifyAlignmentChanged();
			}

		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.EditableComposite#contains(ghidra.program.model.data.DataType)
	 */
	public boolean contains(DataType dataType) {
		lock.acquire();
		try {
			checkIsValid();
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponent dtc = components.get(i);
				DataType dt = dtc.getDataType();

				if (dt == dataType) {
					return true;
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.EditableComposite#isPartOf(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isPartOf(DataType dataType) {
		lock.acquire();
		try {
			checkIsValid();
			if (equals(dataType)) {
				return true;
			}
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponent dtc = components.get(i);
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

	/**
	 * @see ghidra.program.model.data.Composite#getNumComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	public int getNumComponents() {
		lock.acquire();
		try {
			checkIsValid();
//			if (components.size() == 0) {
//				return 1; // lie
//			}
			return components.size();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Composite#getComponent(int, ghidra.program.model.mem.MemBuffer)
	 */
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

	/**
	 * @see ghidra.program.model.data.Composite#getComponents(ghidra.program.model.mem.MemBuffer)
	 */
	@Override
	public DataTypeComponent[] getComponents() {
		lock.acquire();
		try {
			checkIsValid();
			return components.toArray(new DataTypeComponent[components.size()]);
		}
		finally {
			lock.release();
		}
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

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
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

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeSizeChanged(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeSizeChanged(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			boolean changed = false;
			int oldLength = unionLength;
			unionLength = 0;
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponentDB dtc = components.get(i);
				DataType tmpDt = dtc.getDataType();
				int tmpLen = tmpDt.getLength();
				if ((tmpDt.isEquivalent(dt)) && (tmpLen > 0) && (tmpLen != dtc.getLength())) {
					dtc.setLength(tmpLen, true);
					changed = true;
				}
				unionLength = Math.max(unionLength, dtc.getLength());
			}
			if (changed) {
				adjustInternalAlignment(false);
				updateLength(oldLength, true, false);
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

	public void adjustLength() {
		adjustLength(true);
	}

	public void adjustLength(boolean notify) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = unionLength;
			unionLength = getLength(getDataOrganization(), isInternallyAligned());
			updateLength(oldLength, notify, false);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = unionLength;
			boolean didDelete = false;
			for (int i = components.size() - 1; i >= 0; i--) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.getDataType() == dt) {
					dt.removeParent(this);
					components.remove(i);
					removeComponent(dtc.getKey());
					shiftOrdinals(i, -1);
					didDelete = true;
				}
			}
			if (didDelete) {
				adjustInternalAlignment(false);
				if (unionLength == 0) {
					dataMgr.addDataTypeToDelete(key);
				}
				else {
					updateLength(oldLength, true, false);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 *
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null || !(dt instanceof Union)) {
			return false;
		}

		checkIsValid();
		if (resolving) {
			if (dt.getUniversalID().equals(getUniversalID())) {
				return true;
			}
			return DataTypeUtilities.equalsIgnoreConflict(getPathName(), dt.getPathName());
		}
		Union union = (Union) dt;
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
		return true;
	}

	private void updateLength(int oldLength, boolean notify, boolean setLastChangeTime) {
		if (oldLength != unionLength) {
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, unionLength);
//			record.setLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL,
//				(new Date()).getTime());
			try {
				compositeAdapter.updateRecord(record, setLastChangeTime);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
//			if (notify) {
			notifySizeChanged();
//			}
		}
		else if (notify) {
			dataMgr.dataTypeChanged(this);
		}
	}

	private int computeUnpaddedUnionLength() {
		int unpaddedLength = 0;
		for (int i = 0; i < components.size(); i++) {
			unpaddedLength =
				Math.max(unpaddedLength, ((DataTypeComponent) components.get(i)).getLength());
		}
		return unpaddedLength;
	}

	private void shiftOrdinals(int ordinal, int deltaOrdinal) {
		for (int i = ordinal; i < components.size(); i++) {
			DataTypeComponentDB dtc = components.get(i);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal, true);
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		if (oldDt == this) {
			return;
		}
		lock.acquire();
		try {
			checkDeleted();
			try {
				validateDataType(newDt);
				if (!(newDt instanceof DataTypeDB) ||
					(newDt.getDataTypeManager() != getDataTypeManager())) {
					newDt = resolve(newDt);
				}
				checkAncestry(newDt);
			}
			catch (Exception e) {
				newDt = new ByteDataType();
			}
			boolean changed = false;
			int oldLength = getLength();
			Iterator<DataTypeComponentDB> it = components.iterator();
			while (it.hasNext()) {
				DataTypeComponentDB comp = it.next();
				DataType compDt = comp.getDataType();
				if (oldDt == compDt) {
					oldDt.removeParent(this);
					comp.setDataType(newDt);
					newDt.addParent(this);
					int len = newDt.getLength();
					if (len > 0) {
						comp.setLength(len, true);
					}
					changed = true;
				}
			}
			if (changed) {
				adjustInternalAlignment(false);
				if (oldLength != getLength()) {
					updateLength(oldLength, true, true);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	/**
	 * @see ghidra.program.model.data.DataType#dependsOn(ghidra.program.model.data.DataType)
	 */
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

	public int getLength(DataOrganization dataOrganization, boolean padEnd) {
		int unpaddedLength = computeUnpaddedUnionLength();
		int newLength = unpaddedLength;
		if (padEnd) {
			newLength += getPaddingSize(dataOrganization, unpaddedLength);
		}
		return newLength;
	}

	private int getPaddingSize(DataOrganization dataOrganization, int unpaddedLength) {
		int alignment = dataOrganization.getAlignment(this, unpaddedLength);
		int amountFilled = unpaddedLength % alignment;
		if (amountFilled > 0) {
			return alignment - amountFilled;
		}
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Composite#setAligned(boolean)
	 */
	@Override
	public void setInternallyAligned(boolean aligned) {
		super.setInternallyAligned(aligned);
		adjustInternalAlignment(true);
	}

	@Override
	public void realign() {
		if (isInternallyAligned()) {
			adjustInternalAlignment(true);
		}
	}

	@Override
	public void adjustInternalAlignment(boolean notify) {
		adjustLength(notify);
	}
}
