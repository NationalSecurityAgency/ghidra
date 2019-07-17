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
import ghidra.util.exception.InvalidInputException;

/**
 * Structure implementation for the Database.
 *
 *
 */
class StructureDB extends CompositeDB implements Structure {
	private static OrdinalComparator ordinalComparator = new OrdinalComparator();
	private static OffsetComparator offsetComparator = new OffsetComparator();
	private static ComponentComparator componentComparator = new ComponentComparator();
	private int structLength;
	private int numComponents; // If aligned, this does not include the undefined data types.
	private ArrayList<DataTypeComponentDB> components;
	private DataTypeComponentDB flexibleArrayComponent;

	/**
	 * Constructor
	 * @param dataMgr
	 * @param cache
	 * @param compositeAdapter
	 * @param componentAdapter
	 * @param record
	 */
	public StructureDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
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

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.util.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		if (isNotYetDefined()) {
			return "<Empty-Structure>";
		}
		return "";
	}

	/**
	 * @see ghidra.program.model.data.Composite#add(ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	public void add(DataType dataType, int length, String name, String comment, int numCopies) {
		lock.acquire();
		try {
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			for (int ii = 0; ii < numCopies; ++ii) {
				doAdd(dataType, length, name, comment, false, false);
			}
			adjustInternalAlignment(false);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataTypeComponent add(DataType dataType, int length, String name, String comment) {
		if (length < 1) {
			throw new IllegalArgumentException("Minimum component length is 1 byte");
		}
		return doAdd(dataType, length, name, comment, true, true);
	}

	private DataTypeComponent doAdd(DataType dataType, int length, String name, String comment,
			boolean notify, boolean align) {
		lock.acquire();
		try {
			checkDeleted();
			validateDataType(dataType);
			dataType = resolve(dataType);
			checkAncestry(dataType);

			DataTypeComponentDB dtc = null;
			try {
				boolean isFlexibleArray = false;
				if (dataType == DataType.DEFAULT) {
					dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, key,
						numComponents, structLength);
				}
				else {
					int offset = structLength;
					int ordinal = numComponents;
					isFlexibleArray = (length == 0);
					if (length == 0) {
						// assume trailing flexible array component
						offset = -1;
						ordinal = -1;
						isFlexibleArray = true;
						clearFlexibleArrayComponent();
					}
					Record rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key,
						length, ordinal, offset, name, comment);
					dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
					dataType.addParent(this);
					if (isFlexibleArray) {
						flexibleArrayComponent = dtc;
					}
					else {
						components.add(dtc);
					}
				}
				if (!isFlexibleArray) {
					record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL,
						++numComponents);
					structLength += dtc.getLength();
					record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);
					compositeAdapter.updateRecord(record, true);
				}
				if (align) {
					adjustInternalAlignment(false);
				}
				if (notify) {
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

	/**
	 *
	 * @see ghidra.program.model.data.Structure#growStructure(int)
	 */
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

	/**
	 * @see ghidra.program.model.data.EditableComposite#insert(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
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
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			dataType = resolve(dataType);
			checkAncestry(dataType);
			int idx;
			if (isInternallyAligned()) {
				idx = ordinal;
			}
			else {
				idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
			}
			if (idx < 0) {
				idx = -idx - 1;
			}
			if (dataType == DataType.DEFAULT) {
				shiftOffsets(idx, 1, 1);
				notifySizeChanged();
				return getComponent(ordinal);
			}

			// TODO Is this the right place to adjust the length?
			int dtLength = dataType.getLength();
			if (dtLength > 0 && dtLength < length) {
				length = dtLength;
			}

			int offset = getComponent(ordinal).getOffset();
			Record rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, length,
				ordinal, offset, name, comment);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			dataType.addParent(this);
			shiftOffsets(idx, 1, dtc.getLength());
			components.add(idx, dtc);
			adjustInternalAlignment(true);
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
	public void insert(int ordinal, DataType dataType, int length, String name, String comment,
			int numCopies) {
		lock.acquire();
		try {
			checkDeleted();
			if (ordinal < 0 || ordinal > numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			if (ordinal == numComponents) {
				add(dataType, length, name, comment, numCopies);
				return;
			}
			for (int ii = 0; ii < numCopies; ++ii) {
				insert(ordinal + ii, dataType, length, name, comment);
			}
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
			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			int idx;
			if (isInternallyAligned()) {
				idx = ordinal;
			}
			else {
				idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
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
				shiftOffsets(idx, -1, -dtc.getLength());
				adjustInternalAlignment(true);
				notifySizeChanged();
				return;
			}
			idx = -idx - 1;
			shiftOffsets(idx, -1, -1);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
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

			for (int ordinal : ordinals) {
				int idx;
				if (isInternallyAligned()) {
					idx = ordinal;
				}
				else {
					idx = Collections.binarySearch(components, new Integer(ordinal),
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
					shiftOffsets(idx, -1, -dtc.getLength());

				}
				else {
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

	/**
	 * @see ghidra.program.model.data.Composite#getComponent(int, ghidra.program.model.mem.MemBuffer)
	 */
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
			int idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
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

	@Override
	public DataType copy(DataTypeManager dtm) {
		StructureDataType struct =
			new StructureDataType(getCategoryPath(), getName(), getLength(), dtm);
		struct.setDescription(getDescription());
		struct.replaceWith(this);
		return struct;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
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

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
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

	/**
	 * @see ghidra.program.model.data.Structure#clearComponent(int)
	 */
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
				idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
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
	 * @see ghidra.program.model.data.Structure#deleteAtOffset(int)
	 */
	@Override
	public void deleteAtOffset(int offset) {
		lock.acquire();
		try {
			checkDeleted();
			if (offset < 0) {
				throw new IllegalArgumentException("Offset cannot be negative.");
			}
			int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);

			int delta = -1;
			if (index < 0) {
				index = -index - 1;
			}
			else {
				DataTypeComponentDB dtc = components.remove(index);
				dtc.getDataType().removeParent(this);
				try {
					componentAdapter.removeRecord(dtc.getKey());
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
				delta = -dtc.getLength();
			}
			shiftOffsets(index, -1, delta);
			adjustInternalAlignment(true);
			notifySizeChanged();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Structure#getComponentAt(int)
	 */
	@Override
	public DataTypeComponent getComponentAt(int offset) {
		lock.acquire();
		try {
			checkIsValid();
			if (offset >= structLength || offset < 0) {
				return null;
			}
			int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);
			if (index >= 0) {
				return components.get(index);
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

	/**
	 * @see ghidra.program.model.data.Structure#getDataTypeAt(int)
	 */
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

	/**
	 * @see ghidra.program.model.data.Structure#getDefinedComponents()
	 */
	@Override
	public DataTypeComponent[] getDefinedComponents() {
		lock.acquire();
		try {
			checkIsValid();
			return components.toArray(new DataTypeComponent[components.size()]);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Structure#insertAtOffset(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length, String name,
			String comment) {
		lock.acquire();
		try {
			checkDeleted();
			if (offset < 0) {
				throw new IllegalArgumentException("Offset cannot be negative.");
			}
			validateDataType(dataType);
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			dataType = resolve(dataType);
			checkAncestry(dataType);

			if ((offset > structLength) && !isInternallyAligned()) {
				numComponents = numComponents + (offset - structLength);
				structLength = offset;
			}

			int index = Collections.binarySearch(components, new Integer(offset), offsetComparator);

			int additionalShift = 0;
			if (index >= 0) {
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
				shiftOffsets(index, 1 + additionalShift, 1 + additionalShift);
				adjustInternalAlignment(true);
				notifySizeChanged();
				return new DataTypeComponentDB(dataMgr, componentAdapter, this, key, ordinal,
					offset);
			}

			// TODO Is this the right place to adjust the length?
			int dtLength = dataType.getLength();
			if (dtLength > 0 && dtLength < length) {
				length = dtLength;
			}

			Record rec = componentAdapter.createRecord(dataMgr.getResolvedID(dataType), key, length,
				ordinal, offset, name, comment);
			dataType.addParent(this);
			DataTypeComponentDB dtc = new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			shiftOffsets(index, 1 + additionalShift, dtc.getLength() + additionalShift);
			components.add(index, dtc);
			adjustInternalAlignment(true);
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

	/**
	 * @see ghidra.program.model.data.Structure#insertAtOffset(int, ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent insertAtOffset(int offset, DataType dataType, int length) {
		return insertAtOffset(offset, dataType, length, null, null);
	}

	/**
	 * @see ghidra.program.model.data.Structure#replace(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent replace(int ordinal, DataType dataType, int length, String name,
			String comment) {
		lock.acquire();
		try {
			checkDeleted();

			if (ordinal < 0 || ordinal >= numComponents) {
				throw new ArrayIndexOutOfBoundsException(ordinal);
			}
			validateDataType(dataType);
			if (length < 1) {
				throw new IllegalArgumentException("Minimum component length is 1 byte");
			}
			if (dataType == DataType.DEFAULT) {
				clearComponent(ordinal);
				return getComponent(ordinal);
			}
			dataType = resolve(dataType);
			checkAncestry(dataType);

			DataTypeComponent origDtc = getComponent(ordinal);
			DataTypeComponent replaceComponent =
				replaceComponent(origDtc, dataType, length, name, comment, true);
			adjustInternalAlignment(true);
			return replaceComponent;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Structure#replace(int, ghidra.program.model.data.DataType)
	 */
	@Override
	public DataTypeComponent replace(int ordinal, DataType dataType, int length) {
		return replace(ordinal, dataType, length, null, null);
	}

	/**
	 * @see ghidra.program.model.data.Structure#replaceAtOffset(int, ghidra.program.model.data.DataType, int, java.lang.String, java.lang.String)
	 */
	@Override
	public DataTypeComponent replaceAtOffset(int offset, DataType dataType, int length, String name,
			String comment) {
		if (offset >= getLength()) {
			throw new IllegalArgumentException(
				"Can't replace at an offset that doesn't exist in the structure");
		}
		lock.acquire();
		try {
			checkDeleted();
			DataTypeComponent replaceComponent =
				doReplace(offset, dataType, length, name, comment, true);
			adjustInternalAlignment(true);
			return replaceComponent;
		}
		finally {
			lock.release();
		}
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
	 * @see ghidra.program.database.data.DataTypeDB#replaceWith(ghidra.program.model.data.DataType)
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Structure)) {
			throw new IllegalArgumentException();
		}
		doReplaceWith((Structure) dataType, true);
	}

	/**
	 *
	 * @param struct
	 * @param notify
	 */
	void doReplaceWith(Structure struct, boolean notify) {
		doReplaceWith(struct, notify, null);
	}

	/**
	 *
	 * @param struct
	 * @param notify
	 * @param handler
	 */
	void doReplaceWith(Structure struct, boolean notify, DataTypeConflictHandler handler) {
		lock.acquire();
		try {
			checkDeleted();
			int oldLength = structLength;
			long oldMinAlignment = getMinimumAlignment();
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponentDB dtc = components.get(i);
				dtc.getDataType().removeParent(this);
				componentAdapter.removeRecord(dtc.getKey());
			}
			components.clear();
			if (flexibleArrayComponent != null) {
				flexibleArrayComponent.getDataType().removeParent(this);
				componentAdapter.removeRecord(flexibleArrayComponent.getKey());
				flexibleArrayComponent = null;
			}
			if (struct.isNotYetDefined()) {
				numComponents = 0;
				structLength = 0;
			}
			else {
				structLength = struct.getLength();
				numComponents = isInternallyAligned() ? 0 : structLength;
			}
			setAlignment(struct, false);

			setDescription(struct.getDescription());

			DataTypeComponent[] otherComponents = struct.getDefinedComponents();
			for (int i = 0; i < otherComponents.length; i++) {
				DataTypeComponent dtc = otherComponents[i];
				DataType dt = dtc.getDataType();
				if (dt == null) {
					Msg.warn(this,
						"Data type IS NULL: in " + struct.getPathName() + " component " + i);
					continue; // dt can be null if the dt isDeleted by an Undo.
				}
				dt = resolve(dt, handler);
				if (isInternallyAligned()) {
					doAdd(dt, dtc.getLength(), dtc.getFieldName(), dtc.getComment(), false, true);
				}
				else {
					// TODO Is this the right way to get length?
					doReplace(dtc.getOffset(), dt, dtc.getLength(), dtc.getFieldName(),
						dtc.getComment(), false);
				}
			}
			// ok now that all components have been laid down, see if we can make any of them bigger
			// without affecting any offsets
			for (int i = 0; i < components.size(); i++) {
				DataTypeComponent dtc = components.get(i);
				DataType dataType = dtc.getDataType();
				if (dataType.getLength() > dtc.getLength()) {
					int n = consumeBytesAfter(i, dataType.getLength() - dtc.getLength());
					if (n > 0) {
						shiftOffsets(i + 1, 0 - n, 0);
					}
				}
			}

			DataTypeComponent flexComponent = struct.getFlexibleArrayComponent();
			if (flexComponent != null) {
				// set flexible array component
				DataType dt = flexComponent.getDataType();
				if (dt == null) {
					// dt can be null if the dt isDeleted by an Undo.
					Msg.warn(this, "Data type IS NULL: in " + struct.getPathName() +
						" flexible array component");
				}
				else {
					dt = resolve(dt, handler);
					doAdd(dt, 0, flexComponent.getFieldName(), flexComponent.getComment(), false,
						true);
				}
			}

			record.setIntValue(CompositeDBAdapter.COMPOSITE_NUM_COMPONENTS_COL, numComponents);
			record.setIntValue(CompositeDBAdapter.COMPOSITE_LENGTH_COL, structLength);

			compositeAdapter.updateRecord(record, false);

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
		}
		catch (IOException e) {
			dataMgr.dbError(e);
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
			boolean didChange = false;
			int n = components.size();
			for (int i = n - 1; i >= 0; i--) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.getDataType() == dt) {
					dt.removeParent(this);
					components.remove(i);
					shiftOffsets(i, dtc.getLength() - 1, 0);
					try {
						componentAdapter.removeRecord(dtc.getKey());
					}
					catch (IOException e) {
						dataMgr.dbError(e);
					}
					didChange = true;
				}
			}
			if (didChange) {
				adjustInternalAlignment(true);
				dataMgr.dataTypeChanged(this);
			}
		}
		finally {
			lock.release();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see ghidra.program.database.data.DataTypeDB#dataTypeSizeChanged(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeSizeChanged(DataType dt) {
		lock.acquire();
		try {
			checkDeleted();
			if (isInternallyAligned()) {
				adjustInternalAlignment(true);
				return;
			}
			int n = components.size();
			boolean didChange = false;
			for (int i = 0; i < n; i++) {
				DataTypeComponentDB dtc = components.get(i);
				if (dtc.getDataType() == dt) {
					int dtLen = dt.getLength();
					int dtcLen = dtc.getLength();
					if (dtLen < dtcLen) {
						dtc.setLength(dtLen, true);
						shiftOffsets(i + 1, dtcLen - dtLen, 0);
						didChange = true;
					}
					else if (dtLen > dtcLen) {
						int consumed = consumeBytesAfter(i, dtLen - dtcLen);
						if (consumed > 0) {
							dtc.updateRecord();
							shiftOffsets(i + 1, -consumed, 0);
							didChange = true;
						}
					}
				}
			}
			if (didChange) {
				adjustInternalAlignment(true);
				notifySizeChanged();
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		// TODO
		lock.acquire();
		try {
			checkDeleted();
//			if (isInternallyAligned()) {
			adjustInternalAlignment(true);
//				return;
//			}
//			int n = components.size();
//			boolean didChange = false;
//			for(int i=0;i<n;i++) {
//				DataTypeComponentDB dtc = components.get(i);
//				if (dtc.getDataType() == dt) {
//					int dtLen = dt.getLength();
//					int dtcLen = dtc.getLength();
//					if (dtLen < dtcLen) {
//						dtc.setLength(dtLen);
//						dtc.updateRecord();
//						shiftOffsets(i+1, dtcLen-dtLen, 0);
//						didChange = true;
//					}
//					else if (dtLen > dtcLen) {
//						int consumed = consumeBytesAfter(i, dtLen-dtcLen);
//						if (consumed > 0) {
//							dtc.updateRecord();
//							shiftOffsets(i+1, -consumed, 0);
//							didChange = true;
//						}
//					}
//				}
//			}
//			if (didChange) {
//				notifySizeChanged();
//			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dataType) {

		if (dataType == this) {
			return true;
		}
		if (dataType == null || !(dataType instanceof Structure)) {
			return false;
		}

		checkIsValid();
		if (resolving) {
			if (dataType.getUniversalID().equals(getUniversalID())) {
				return true;
			}
			return DataTypeUtilities.equalsIgnoreConflict(getPathName(), dataType.getPathName());
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

//	private boolean hasRoom(int index, int offset, int length) {
//		if (offset+length > this.structLength) {
//			return false;
//		}
//		if (index+1 < components.size()) {
//			DataTypeComponent nextDtc = (DataTypeComponent)components.get(index+1);
//			return offset+length <= nextDtc.getOffset();
//		}
//		return true;
//	}

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
			dtc.setOffset(dtc.getOffset() + deltaOffset, false);
			dtc.setOrdinal(dtc.getOrdinal() + deltaOrdinal, false);
			dtc.updateRecord();
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

	/**
	 * Replace the component and send a notification according to the
	 * doNotify param.
	 */
	private DataTypeComponent doReplace(int offset, DataType dataType, int length, String name,
			String comment, boolean doNotify) {

		if (offset < 0) {
			throw new IllegalArgumentException("Offset cannot be negative.");
		}
		validateDataType(dataType);
		if (length < 1) {
			throw new IllegalArgumentException("Minimum component length is 1 byte");
		}
		dataType = resolve(dataType);
		checkAncestry(dataType);

		// TODO Is this the right place to adjust the length?
		int dtLength = dataType.getLength();
		if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}

		DataTypeComponent origDtc = getComponentAt(offset);
		if (dataType == DataType.DEFAULT) {
			int ordinal = origDtc.getOrdinal();
			clearComponent(ordinal);
			return getComponent(ordinal);
		}
		return replaceComponent(origDtc, dataType, length, name, comment, doNotify);
	}

	/**
	 * Replace the indicated component with a new component containing the
	 * specified data type.
	 * @param origDtc the original data type component in this structure.
	 * @param resolvedDataType the data type of the new component
	 * @param length the length of the new component
	 * @param name the field name of the new component
	 * @param comment the comment for the new component
	 * @return the new component or null if the new component couldn't fit.
	 */
	private DataTypeComponent replaceComponent(DataTypeComponent origDtc, DataType resolvedDataType,
			int length, String name, String comment, boolean doNotify) {
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
			Record rec = componentAdapter.createRecord(dataMgr.getResolvedID(resolvedDataType), key,
				length, ordinal, newOffset, name, comment);
			resolvedDataType.addParent(this);
			DataTypeComponentDB newDtc =
				new DataTypeComponentDB(dataMgr, componentAdapter, this, rec);
			int index;
			if (isInternallyAligned()) {
				index = ordinal;
			}
			else {
				index =
					Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
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
	 * Gets the number of Undefined bytes beginning at the indicated component
	 * ordinal. Undefined bytes that have a field name or comment specified are
	 * also included.
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
		int idx = Collections.binarySearch(components, new Integer(ordinal), ordinalComparator);
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
				newDt = DataType.DEFAULT;
			}
			boolean changed = false;
			int nextIndex = 0; // index of next defined component.
			Iterator<DataTypeComponentDB> it = components.iterator();
			while (it.hasNext()) {
				nextIndex++;
				DataTypeComponentDB comp = it.next();
				DataType compDt = comp.getDataType();
				if (oldDt == compDt) {
					oldDt.removeParent(this);
					comp.setDataType(newDt);
					newDt.addParent(this);
					int len = newDt.getLength();
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
							else if (comp.getOrdinal() == getLastDefinedComponentIndex()) { // we are the last defined component, grow structure
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
					changed = true;
				}
			}
			if (changed) {
				notifySizeChanged();
			}
		}
		finally {
			lock.release();
		}
		adjustInternalAlignment(true);
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
	}

	/* (non-Javadoc)
	 * @see ghidra.program.model.data.Structure#deleteAll()
	 */
	@Override
	public void deleteAll() {
		lock.acquire();
		try {
			checkDeleted();

			if (flexibleArrayComponent != null) {
				try {
					componentAdapter.removeRecord(flexibleArrayComponent.getKey());
				}
				catch (IOException e) {
					dataMgr.dbError(e);
				}
				flexibleArrayComponent = null;
			}

			for (int i = 0; i < components.size(); i++) {
				DataTypeComponentDB dtc = components.get(i);
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
			try {
				compositeAdapter.updateRecord(record, true);
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

	private static class OffsetComparator implements Comparator<Object> {

		/**
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Integer) {
				return -compare(o2, o1);
			}
			DataTypeComponent dtc = (DataTypeComponent) o1;
			int offset = ((Integer) o2).intValue();
			if (offset < dtc.getOffset()) {
				return 1;
			}
			else if (offset > dtc.getEndOffset()) {
				return -1;
			}
			return 0;
		}

	}

	private static class OrdinalComparator implements Comparator<Object> {

		/**
		 * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
		 */
		@Override
		public int compare(Object o1, Object o2) {
			if (o1 instanceof Integer) {
				return -compare(o2, o1);
			}
			DataTypeComponent dtc = (DataTypeComponent) o1;
			int ordinal = ((Integer) o2).intValue();
			return dtc.getOrdinal() - ordinal;
		}

	}

	private static class ComponentComparator implements Comparator<DataTypeComponent> {
		@Override
		public int compare(DataTypeComponent dtc1, DataTypeComponent dtc2) {
			return dtc1.getOrdinal() - dtc2.getOrdinal();
		}
	}

	/**
	 * Adjust the alignment, packing and padding of components within this structure based upon the
	 * current alignment and packing attributes for this structure. This method should be
	 * called to basically fix up the layout of the internal components of the structure
	 * after other code has changed the attributes of the structure.
	 * <BR>When switching between internally aligned and unaligned this method corrects the
	 * component ordinal numbering also.
	 * @param notify if true this method will do data type change notification
	 * when it changes the layout of the components or when it changes the
	 * overall size of the structure.
	 * @return true if the structure was changed by this method.
	 */
	private boolean adjustComponents(boolean notify) {
		boolean internallyAligned = isInternallyAligned();
		boolean keepDefinedDefaults = !internallyAligned;

		lock.acquire();
		try {
			checkDeleted();
			int oldLength = structLength;

			if (!isInternallyAligned()) {
				boolean changed = adjustUnalignedComponents();
				if (notify && changed) {
					dataMgr.dataTypeChanged(this);
				}
				return changed;
			}

			boolean compositeDBChanged = false;
			boolean componentsDBChanged = false;
			int packingAlignment = getPackingValue();

			// Adjust each of the components.
			int currentOrdinal = 0;
			int currentOffset = 0;
			int allComponentsLCM = 1;
			for (DataTypeComponentDB dataTypeComponent : components) {

				DataType componentDt = dataTypeComponent.getDataType();
				if (!keepDefinedDefaults && DataType.DEFAULT == componentDt) {
					continue; // Discard a defined Default data type.
				}
				int componentLength = dataTypeComponent.getLength();
				int componentOrdinal = dataTypeComponent.getOrdinal();
				int componentOffset = dataTypeComponent.getOffset();
				int dtLength = componentDt.getLength();
				if (dtLength <= 0) {
					dtLength = componentLength;
				}

				int componentAlignment =
					getPackedAlignment(componentDt, dtLength, packingAlignment);

				allComponentsLCM = DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM,
					componentAlignment);

				int newOffset = DataOrganizationImpl.getOffset(componentAlignment, currentOffset);
				currentOffset = newOffset + dtLength;
				if (componentOrdinal == currentOrdinal && componentOffset == newOffset &&
					componentLength == dtLength) {
					currentOrdinal++;
					continue; // No change needed.
				}
				dataTypeComponent.setOffset(newOffset, false);
				dataTypeComponent.setOrdinal(currentOrdinal, false);
				dataTypeComponent.setLength(dtLength, false);
				dataTypeComponent.updateRecord();
				currentOrdinal++;
				componentsDBChanged = true;
			}

			if (flexibleArrayComponent != null) {
				// account for flexible array type in any end of structure padding
				DataType dataType = flexibleArrayComponent.getDataType();
				int componentAlignment =
					getPackedAlignment(dataType, dataType.getLength(), packingAlignment);
				currentOffset = DataOrganizationImpl.getOffset(componentAlignment, currentOffset);
				allComponentsLCM = DataOrganizationImpl.getLeastCommonMultiple(allComponentsLCM,
					componentAlignment);
			}

			// Adjust the structure
			compositeDBChanged = updateComposite(currentOrdinal, currentOffset, false);

			boolean addedPadding = alignEndOfStruct(allComponentsLCM);

			if (notify) {
				if (componentsDBChanged || compositeDBChanged || addedPadding) {
					if (oldLength != structLength) {
						notifySizeChanged();
					}
					else {
						dataMgr.dataTypeChanged(this);
					}
					return true;
				}
			}
			return false;
		}
		finally {
			lock.release();
		}
	}

	private int getPackedAlignment(DataType componentDt, int dtLength, int packingAlignment) {
		DataOrganization dataOrganization = getDataOrganization();
		int componentAlignment = dataOrganization.getAlignment(componentDt, dtLength);
		int componentForcedAlignment = dataOrganization.getForcedAlignment(componentDt);
		boolean componentForcingAlignment = componentForcedAlignment > 0;
		if (componentForcingAlignment) {
			componentAlignment = DataOrganizationImpl.getLeastCommonMultiple(componentAlignment,
				componentForcedAlignment);
		}
		if (packingAlignment > 0) {
			if (componentForcedAlignment > packingAlignment) {
				componentAlignment = componentForcedAlignment;
			}
			else if (componentAlignment > packingAlignment) {
				componentAlignment = packingAlignment;
			}
		}
		return componentAlignment;
	}

	private boolean adjustUnalignedComponents() {
		boolean changed = false;
		int currentOrdinal = 0;
		int componentCount = 0;
		int currentOffset = 0;
		for (DataTypeComponentDB dataTypeComponent : components) {
			int componentLength = dataTypeComponent.getLength();
			int componentOffset = dataTypeComponent.getOffset();
			int numUndefinedsBefore = componentOffset - currentOffset;
			componentCount += numUndefinedsBefore;
			currentOffset += numUndefinedsBefore;
			currentOrdinal += numUndefinedsBefore;
			componentCount++;
			currentOffset += componentLength;
			if (dataTypeComponent.getOrdinal() != currentOrdinal) {
				dataTypeComponent.setOrdinal(currentOrdinal, true);
				changed = true;
			}
			currentOrdinal++;
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
			boolean setLastChangeTime) {
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

	private boolean alignEndOfStruct(int componentLCM) {
		int minimumAlignment = getMinimumAlignment();
		int structureLength = getLength();
		if (structureLength == 0) {
			return true;
		}
		int overallAlignment = componentLCM;
		if (minimumAlignment > overallAlignment) {
			// TODO Should this actually get the LeastCommonMultiple of minimumAlignment and overallAlignment?
			overallAlignment = minimumAlignment;
		}
		int padSize = DataOrganizationImpl.getPaddingSize(overallAlignment, structLength); // FIXME Fix cast.
		if (padSize > 0) {
			doGrowStructure(padSize);
			return true;
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
	public void pack(int packingSize) throws InvalidInputException {
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
	public DataTypeComponent getFlexibleArrayComponent() {
		return flexibleArrayComponent;
	}

	@Override
	public DataTypeComponent setFlexibleArrayComponent(DataType flexType, String name,
			String comment) {
		return doAdd(flexType, 0, name, comment, true, true);
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
