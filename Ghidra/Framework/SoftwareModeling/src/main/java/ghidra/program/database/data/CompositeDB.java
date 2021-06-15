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

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

/**
 * Database implementation for a structure or union.
 */
abstract class CompositeDB extends DataTypeDB implements CompositeInternal {

	protected CompositeDBAdapter compositeAdapter;
	protected ComponentDBAdapter componentAdapter;

	/**
	 * Constructor for a composite data type (structure or union).
	 * 
	 * @param dataMgr          the data type manager containing this data type.
	 * @param cache            DataTypeDB object cache
	 * @param compositeAdapter the database adapter for this data type.
	 * @param componentAdapter the database adapter for the components of this data
	 *                         type.
	 * @param record           the database record for this data type.
	 */
	CompositeDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache,
			CompositeDBAdapter compositeAdapter, ComponentDBAdapter componentAdapter,
			DBRecord record) {
		super(dataMgr, cache, record);
		this.compositeAdapter = compositeAdapter;
		this.componentAdapter = componentAdapter;
		initialize();
	}

	/**
	 * Perform initialization of instance fields during instantiation or instance
	 * refresh
	 */
	protected abstract void initialize();

	/**
	 * Get the preferred length for a new component. For Unions and internally
	 * aligned structures the preferred component length for a fixed-length dataType
	 * will be the length of that dataType. Otherwise the length returned will be no
	 * larger than the specified length.
	 * 
	 * @param dataType new component datatype
	 * @param length   constrained length or -1 to force use of dataType size.
	 *                 Dynamic types such as string must have a positive length
	 *                 specified.
	 * @return preferred component length
	 */
	protected int getPreferredComponentLength(DataType dataType, int length) {
		if ((isPackingEnabled() || (this instanceof Union)) && !(dataType instanceof Dynamic)) {
			length = -1; // force use of datatype size
		}
		int dtLength = dataType.getLength();
		if (length <= 0) {
			length = dtLength;
		}
		else if (dtLength > 0 && dtLength < length) {
			length = dtLength;
		}
		if (length <= 0) {
			throw new IllegalArgumentException("Positive length must be specified for " +
				dataType.getDisplayName() + " component");
		}
		return length;
	}

	@Override
	protected String doGetName() {
		return record.getString(CompositeDBAdapter.COMPOSITE_NAME_COL);
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(CompositeDBAdapter.COMPOSITE_CAT_COL);
	}

	/**
	 * Handle replacement of datatype which may impact bitfield datatype.
	 * 
	 * @param bitfieldComponent bitfield component
	 * @param oldDt             affected datatype which has been removed or replaced
	 * @param newDt             replacement datatype
	 * @return                  true if bitfield component was modified
	 * @throws InvalidDataTypeException if bitfield was based upon oldDt but new
	 *                                  datatype is invalid for a bitfield
	 */
	protected boolean updateBitFieldDataType(DataTypeComponentDB bitfieldComponent, DataType oldDt,
			DataType newDt) throws InvalidDataTypeException {
		if (!bitfieldComponent.isBitFieldComponent()) {
			throw new AssertException("expected bitfield component");
		}

		BitFieldDBDataType bitfieldDt = (BitFieldDBDataType) bitfieldComponent.getDataType();
		if (bitfieldDt.getBaseDataType() != oldDt) {
			return false;
		}

		if (newDt != null) {
			BitFieldDataType.checkBaseDataType(newDt);
			int maxBitSize = 8 * newDt.getLength();
			if (bitfieldDt.getBitSize() > maxBitSize) {
				throw new InvalidDataTypeException("Replacement datatype too small for bitfield");
			}
		}

		try {
			BitFieldDBDataType newBitfieldDt = new BitFieldDBDataType(newDt,
				bitfieldDt.getDeclaredBitSize(), bitfieldDt.getBitOffset());
			bitfieldComponent.setDataType(newBitfieldDt);
			oldDt.removeParent(this);
			newDt.addParent(this);
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException("unexpected");
		}

		return true;
	}

	@Override
	protected boolean refresh() {
		try {
			DBRecord rec = compositeAdapter.getRecord(key);
			if (rec != null) {
				record = rec;
				initialize();
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	@Override
	public void setDescription(String desc) {
		lock.acquire();
		try {
			checkDeleted();
			record.setString(CompositeDBAdapter.COMPOSITE_COMMENT_COL, desc);
			try {
				compositeAdapter.updateRecord(record, true);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getDescription() {
		lock.acquire();
		try {
			checkIsValid();
			String s = record.getString(CompositeDBAdapter.COMPOSITE_COMMENT_COL);
			return s == null ? "" : s;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public abstract boolean hasLanguageDependantLength();
	
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		return null;
	}

	@Override
	public final DataTypeComponent add(DataType dataType) {
		return add(dataType, -1, null, null);
	}

	@Override
	public final DataTypeComponent add(DataType dataType, int length) {
		return add(dataType, length, null, null);
	}

	@Override
	public final DataTypeComponent add(DataType dataType, String fieldName, String comment) {
		return add(dataType, -1, fieldName, comment);
	}

	@Override
	public final DataTypeComponent insert(int ordinal, DataType dataType, int length) {
		return insert(ordinal, dataType, length, null, null);
	}

	@Override
	public final DataTypeComponent insert(int ordinal, DataType dataType) {
		return insert(ordinal, dataType, -1, null, null);
	}

	@Override
	public String getMnemonic(Settings settings) {
		return getDisplayName();
	}

	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(CompositeDBAdapter.COMPOSITE_CAT_COL, categoryID);
		compositeAdapter.updateRecord(record, false);
	}

	@Override
	public boolean isPartOf(DataType dataTypeOfInterest) {
		lock.acquire();
		try {
			checkIsValid();
			return DataTypeUtilities.isSecondPartOfFirst(this, dataTypeOfInterest);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * This method throws an exception if the indicated data type is an ancestor of
	 * this data type. In other words, the specified data type has a component or
	 * sub-component containing this data type.
	 * 
	 * @param dataType the data type
	 * @throws DataTypeDependencyException if the data type is an ancestor of this
	 *                                     data type.
	 */
	protected void checkAncestry(DataType dataType) throws DataTypeDependencyException {
		if (this.equals(dataType)) {
			throw new DataTypeDependencyException(
				"Data type " + getDisplayName() + " can't contain itself.");
		}
		else if (DataTypeUtilities.isSecondPartOfFirst(dataType, this)) {
			throw new DataTypeDependencyException("Data type " + dataType.getDisplayName() +
				" has " + getDisplayName() + " within it.");
		}
	}

	protected DataType doCheckedResolve(DataType dt)
			throws DataTypeDependencyException {
		if (dt instanceof Pointer) {
			pointerPostResolveRequired = true;
			return resolve(((Pointer) dt).newPointer(DataType.DEFAULT));
		}
		dt = resolve(dt);
		checkAncestry(dt);
		return dt;
	}

	@Override
	protected void doSetNameRecord(String name) throws IOException {
		record.setString(CompositeDBAdapter.COMPOSITE_NAME_COL, name);
		compositeAdapter.updateRecord(record, true);
	}

	/**
	 * This method throws an exception if the indicated data type is not a valid
	 * data type for a component of this composite data type.  If the DEFAULT 
	 * datatype is specified when unsupported an Undefined1 will be returned 
	 * in its place (e.g., packing enabled, Union).
	 * 
	 * @param dataType the data type to be checked.
	 * @return datatype to be used for insert/add
	 * @throws IllegalArgumentException if the data type is invalid.
	 */
	protected DataType validateDataType(DataType dataType) {
		if (dataType == DataType.DEFAULT) {
			if (isPackingEnabled() || (this instanceof Union)) {
				return Undefined1DataType.dataType;
			}
			return dataType;
		}
		if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			if (!dynamicDataType.canSpecifyLength()) {
				throw new IllegalArgumentException("The \"" + dataType.getName() +
					"\" data type is not allowed in a composite data type.");
			}
		}
		else if (dataType instanceof FactoryDataType || dataType.getLength() <= 0) {
			throw new IllegalArgumentException("The \"" + dataType.getName() +
				"\" data type is not allowed in a composite data type.");
		}
		return dataType;
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return record.getLongValue(CompositeDBAdapter.COMPOSITE_SOURCE_SYNC_TIME_COL);
	}

	@Override
	public long getLastChangeTime() {
		return record.getLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL);
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(CompositeDBAdapter.COMPOSITE_LAST_CHANGE_TIME_COL, lastChangeTime);
			compositeAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(CompositeDBAdapter.COMPOSITE_SOURCE_SYNC_TIME_COL, lastChangeTime);
			compositeAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public UniversalID getUniversalID() {
		return new UniversalID(record.getLongValue(CompositeDBAdapter.COMPOSITE_UNIVERSAL_DT_ID));
	}

	@Override
	void setUniversalID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(CompositeDBAdapter.COMPOSITE_UNIVERSAL_DT_ID, id.getValue());
			compositeAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}

	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return new UniversalID(
			record.getLongValue(CompositeDBAdapter.COMPOSITE_SOURCE_ARCHIVE_ID_COL));
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(CompositeDBAdapter.COMPOSITE_SOURCE_ARCHIVE_ID_COL, id.getValue());
			compositeAdapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}

	}

	protected final int getNonPackedAlignment() {
		int alignment;
		int minimumAlignment = getStoredMinimumAlignment();
		if (minimumAlignment == DEFAULT_ALIGNMENT) {
			alignment = 1;
		}
		else if (minimumAlignment == MACHINE_ALIGNMENT) {
			alignment = getDataOrganization().getMachineAlignment();
		}
		else {
			alignment = minimumAlignment;
		}
		return alignment;
	}

	/**
	 * Get computed alignment and optionally update record.  May only be invoked with
	 * lock acquired.
	 * @param updateRecord if true record should be updated without timestamp change
	 * @return computed alignment
	 */
	protected abstract int getComputedAlignment(boolean updateRecord);

	@Override
	public final int getAlignment() {
		lock.acquire();
		try {
			return getComputedAlignment(checkIsValid() && dataMgr.isTransactionActive());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public final void repack() {
		lock.acquire();
		try {
			checkDeleted();
			repack(false, true);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Repack components within this composite based on the current packing, alignment 
	 * and {@link DataOrganization} settings.  Non-packed Structures: change detection
	 * is limited to component count and length is assumed to already be correct.
	 * May only be invoked with lock acquired.
	 * <p>
	 * NOTE: If modifications to stored length are made prior to invoking this method, 
	 * detection of a size change may not be possible.  
	 * <p>
	 * NOTE: Currently a change in calculated alignment can not be provided since
	 * this value is not stored.
	 * 
	 * @param isAutoChange true if changes are in response to another another datatype's change.
	 * @param notify if true notification will be sent to parents if a size change
	 * or component placement change is detected.
	 * @return true if a layout change was detected.
	 */
	protected abstract boolean repack(boolean isAutoChange, boolean notify);

	@Override
	public int getStoredPackingValue() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getIntValue(CompositeDBAdapter.COMPOSITE_PACKING_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public PackingType getPackingType() {
		int packing = getStoredPackingValue();
		if (packing < DEFAULT_PACKING) {
			return PackingType.DISABLED;
		}
		if (packing == DEFAULT_PACKING) {
			return PackingType.DEFAULT;
		}
		return PackingType.EXPLICIT;
	}

	@Override
	public int getExplicitPackingValue() {
		return getStoredPackingValue();
	}

	@Override
	public void setExplicitPackingValue(int packingValue) {
		if (packingValue <= 0) {
			throw new IllegalArgumentException(
				"explicit packing value must be positive: " + packingValue);
		}
		setStoredPackingValue(packingValue);
	}

	@Override
	public void setToDefaultPacking() {
		setStoredPackingValue(DEFAULT_PACKING);
	}

	private void setStoredPackingValue(int packingValue) {
		if (packingValue < NO_PACKING) {
			throw new IllegalArgumentException("invalid packing value: " + packingValue);
		}
		lock.acquire();
		try {
			checkDeleted();
			int oldPackingValue = getStoredPackingValue();
			if (packingValue == oldPackingValue) {
				return;
			}
			if (oldPackingValue == NO_PACKING || packingValue == NO_PACKING) {
				// force default alignment when transitioning to or from disabled packing
				record.setIntValue(CompositeDBAdapter.COMPOSITE_MIN_ALIGN_COL, DEFAULT_ALIGNMENT);
			}
			record.setIntValue(CompositeDBAdapter.COMPOSITE_PACKING_COL, packingValue);
			compositeAdapter.updateRecord(record, true);
			if (!repack(false, true)) {
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
	public AlignmentType getAlignmentType() {
		int minimumAlignment = getStoredMinimumAlignment();
		if (minimumAlignment < DEFAULT_ALIGNMENT) {
			return AlignmentType.MACHINE;
		}
		if (minimumAlignment == DEFAULT_ALIGNMENT) {
			return AlignmentType.DEFAULT;
		}
		return AlignmentType.EXPLICIT;
	}

	@Override
	public void setToDefaultAligned() {
		setStoredMinimumAlignment(DEFAULT_ALIGNMENT);
	}

	@Override
	public void setToMachineAligned() {
		setStoredMinimumAlignment(MACHINE_ALIGNMENT);
	}

	@Override
	public int getExplicitMinimumAlignment() {
		return getStoredMinimumAlignment();
	}

	@Override
	public int getStoredMinimumAlignment() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getIntValue(CompositeDBAdapter.COMPOSITE_MIN_ALIGN_COL);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setExplicitMinimumAlignment(int minimumAlignment) {
		if (minimumAlignment <= 0) {
			throw new IllegalArgumentException(
				"explicit minimum alignment must be positive: " + minimumAlignment);
		}
		setStoredMinimumAlignment(minimumAlignment);
	}

	private void setStoredMinimumAlignment(int minimumAlignment) {
		if (minimumAlignment < MACHINE_ALIGNMENT) {
			throw new IllegalArgumentException(
				"invalid minimum alignment value: " + minimumAlignment);
		}
		lock.acquire();
		try {
			checkDeleted();
			if (minimumAlignment == getStoredMinimumAlignment()) {
				return;
			}
			record.setIntValue(CompositeDBAdapter.COMPOSITE_MIN_ALIGN_COL, minimumAlignment);
			compositeAdapter.updateRecord(record, true);
			if (!repack(false, true)) {
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
	public abstract DataTypeComponentDB[] getDefinedComponents();

	@Override
	protected void postPointerResolve(DataType definitionDt, DataTypeConflictHandler handler) {
		Composite composite = (Composite) definitionDt;
		DataTypeComponent[] definedComponents = composite.getDefinedComponents();
		DataTypeComponentDB[] myDefinedComponents = getDefinedComponents();
		if (definedComponents.length != myDefinedComponents.length) {
			throw new IllegalArgumentException("mismatched definition datatype");
		}
		for (int i = 0; i < definedComponents.length; i++) {
			DataTypeComponent dtc = definedComponents[i];
			DataType dt = dtc.getDataType();
			if (dt instanceof Pointer) {
				DataTypeComponentDB myDtc = myDefinedComponents[i];
				myDtc.getDataType().removeParent(this);
				dt = dataMgr.resolve(dt, handler);
				myDtc.setDataType(dt);
				dt.addParent(this);
			}
		}
	}

	@Override
	public void setPackingEnabled(boolean enabled) {
		if (enabled == isPackingEnabled()) {
			return;
		}
		setStoredPackingValue(enabled ? DEFAULT_PACKING : NO_PACKING);
	}

	/**
	 * Copy packing and alignment settings from specified composite without
	 * repacking or notification.
	 * @param composite instance whose packing and alignment are to be copied
	 * @throws IOException if database IO error occured
	 */
	protected void doSetPackingAndAlignment(CompositeInternal composite) throws IOException {
		record.setIntValue(CompositeDBAdapter.COMPOSITE_MIN_ALIGN_COL,
			composite.getStoredMinimumAlignment());
		record.setIntValue(CompositeDBAdapter.COMPOSITE_PACKING_COL,
			composite.getStoredPackingValue());
		compositeAdapter.updateRecord(record, true);
	}

	@Override
	public String toString() {
		return CompositeDataTypeImpl.toString(this);
	}
	
	/**
	 * Perform any neccessary component adjustments based on
	 * sizes and alignment of components differing from their 
	 * specification which may be influenced by the data organization.
	 * If this composite changes parents will not be
	 * notified - handling this is the caller's responsibility.
	 * @throws IOException if database IO error occurs
	 */
	protected abstract void fixupComponents() throws IOException;
}
