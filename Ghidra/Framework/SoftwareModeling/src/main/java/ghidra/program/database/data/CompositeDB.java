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

import db.Record;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.UniversalID;
import ghidra.util.exception.AssertException;

/**
 * Database implementation for a structure or union.
 */
abstract class CompositeDB extends DataTypeDB implements Composite {

	// Internal Alignment Constants
	protected static final int UNALIGNED = CompositeDBAdapter.UNALIGNED;
	protected static final int ALIGNED_NO_PACKING = CompositeDBAdapter.ALIGNED_NO_PACKING;
	// Otherwise the packing value (1 to (2**32 - 1)).

	// External (Minimum) Alignment Constants
	protected static final int MACHINE_ALIGNED = CompositeDBAdapter.MACHINE_ALIGNED;
	protected static final int DEFAULT_ALIGNED = CompositeDBAdapter.DEFAULT_ALIGNED;
	// Otherwise the alignment value (1 to (2**32 - 1)).

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
			Record record) {
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
		if ((isInternallyAligned() || (this instanceof Union)) && !(dataType instanceof Dynamic)) {
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
	 * @param                   true if bitfield component was modified
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
			Record rec = compositeAdapter.getRecord(key);
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
	public boolean isDynamicallySized() {
		return isInternallyAligned();
	}

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
	 * data type for a component of this composite data type.
	 * 
	 * @param dataType the data type to be checked.
	 * @throws IllegalArgumentException if the data type is invalid.
	 */
	protected void validateDataType(DataType dataType) {
		if (isInternallyAligned() && dataType == DataType.DEFAULT) {
			throw new IllegalArgumentException(
				"The DEFAULT data type is not allowed in an aligned composite data type.");
		}
		if (dataType instanceof FactoryDataType) {
			throw new IllegalArgumentException("The \"" + dataType.getName() +
				"\" data type is not allowed in a composite data type.");
		}
		else if (dataType instanceof Dynamic) {
			Dynamic dynamicDataType = (Dynamic) dataType;
			if (!dynamicDataType.canSpecifyLength()) {
				throw new IllegalArgumentException("The \"" + dataType.getName() +
					"\" data type is not allowed in a composite data type.");
			}
		}
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
			dataMgr.dataTypeChanged(this);
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
			dataMgr.dataTypeChanged(this);
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
			dataMgr.dataTypeChanged(this);
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
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}

	}

	@Override
	public int getPackingValue() {
		int dbValue = record.getIntValue(CompositeDBAdapter.COMPOSITE_INTERNAL_ALIGNMENT_COL);
		if (dbValue == CompositeDB.UNALIGNED || dbValue == CompositeDB.ALIGNED_NO_PACKING) {
			return 0;
		}
		return dbValue;
	}

	@Override
	public void setPackingValue(int packingValue) {
		boolean changed = false;
		if (!isInternallyAligned()) {
			doSetInternallyAligned(true);
			changed = true;
		}
		if (packingValue != getPackingValue()) {
			doSetPackingValue(packingValue);
			changed = true;
		}
		if (changed) {
			adjustInternalAlignment(false);
			notifyAlignmentChanged();
		}
	}

	public void doSetPackingValue(int packingValue) {
		if (packingValue < 0) {
			packingValue = NOT_PACKING;
		}
		lock.acquire();
		try {
			checkDeleted();
			if (packingValue == getPackingValue()) {
				return;
			}
			int dbPackingValue;
			if (packingValue == NOT_PACKING) {
				if (isInternallyAligned()) {
					dbPackingValue = ALIGNED_NO_PACKING;
				}
				else {
					dbPackingValue = UNALIGNED;
				}
			}
			else {
				dbPackingValue = packingValue;
			}
			record.setIntValue(CompositeDBAdapter.COMPOSITE_INTERNAL_ALIGNMENT_COL, dbPackingValue);
			compositeAdapter.updateRecord(record, true);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isDefaultAligned() {
		int dbValue = record.getIntValue(CompositeDBAdapter.COMPOSITE_EXTERNAL_ALIGNMENT_COL);
		return (dbValue == CompositeDB.DEFAULT_ALIGNED);
	}

	@Override
	public boolean isMachineAligned() {
		int dbValue = record.getIntValue(CompositeDBAdapter.COMPOSITE_EXTERNAL_ALIGNMENT_COL);
		return (dbValue == CompositeDB.MACHINE_ALIGNED);
	}

	@Override
	public int getMinimumAlignment() {
		int dbValue = record.getIntValue(CompositeDBAdapter.COMPOSITE_EXTERNAL_ALIGNMENT_COL);
		if (dbValue == CompositeDB.MACHINE_ALIGNED) {
			return getMachineAlignment();
		}
		if (dbValue == CompositeDB.DEFAULT_ALIGNED) {
			return getDefaultAlignment();
		}
		return dbValue;
	}

	private int getDefaultAlignment() {
		return Composite.DEFAULT_ALIGNMENT_VALUE;
	}

	private int getMachineAlignment() {
		return dataMgr.getDataOrganization().getMachineAlignment();
	}

	@Override
	public void setMinimumAlignment(int externalAlignment) {
		boolean changed = false;
		if (!isInternallyAligned()) {
			doSetInternallyAligned(true);
			changed = true;
		}
		if (doSetMinimumAlignment(externalAlignment)) {
			changed = true;
		}
		if (changed) {
			adjustInternalAlignment(false);
			notifyAlignmentChanged();
		}
	}

	public boolean doSetMinimumAlignment(int externalAlignment) {
		if (externalAlignment < 1) {
			externalAlignment = DEFAULT_ALIGNED;
		}
		return modifyAlignment(externalAlignment);
	}

	@Override
	public void setToDefaultAlignment() {
		boolean changed = false;
		if (!isInternallyAligned()) {
			doSetInternallyAligned(true);
			changed = true;
		}
		if (doSetToDefaultAlignment()) {
			changed = true;
		}
		if (changed) {
			adjustInternalAlignment(false);
			notifyAlignmentChanged();
		}
	}

	public boolean doSetToDefaultAlignment() {
		return modifyAlignment(CompositeDB.DEFAULT_ALIGNED);
	}

	@Override
	public void setToMachineAlignment() {
		boolean changed = false;
		if (!isInternallyAligned()) {
			doSetInternallyAligned(true);
			changed = true;
		}
		if (doSetToMachineAlignment()) {
			changed = true;
		}
		if (changed) {
			adjustInternalAlignment(false);
			notifyAlignmentChanged();
		}
	}

	public boolean doSetToMachineAlignment() {
		return modifyAlignment(CompositeDB.MACHINE_ALIGNED);
	}

	private boolean modifyAlignment(int dbExternalAlignment) {
		lock.acquire();
		try {
			checkDeleted();
			if (isMachineAligned()) {
				if (dbExternalAlignment == MACHINE_ALIGNED) {
					return false;
				}
			}
			if (isDefaultAligned()) {
				if (dbExternalAlignment == DEFAULT_ALIGNED) {
					return false;
				}
			}
			else if (dbExternalAlignment == getMinimumAlignment()) {
				return false;
			}
			record.setIntValue(CompositeDBAdapter.COMPOSITE_EXTERNAL_ALIGNMENT_COL,
				dbExternalAlignment);
			compositeAdapter.updateRecord(record, true);
			return true;
		}
		catch (IOException e) {
			dataMgr.dbError(e);
			return false;
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

	/**
	 * Notification that this composite data type's alignment has changed.
	 */
	protected void notifyAlignmentChanged() {
		// TODO: This method is not properly invoked when new components are
		// added which could change the alignment of this composite
		for (DataType dt : dataMgr.getParentDataTypes(key)) {
			if (dt instanceof Composite) {
				Composite composite = (Composite) dt;
				composite.dataTypeAlignmentChanged(this);
			}
		}
		dataMgr.dataTypeChanged(this);
	}

	@Override
	public boolean isInternallyAligned() {
		int dbValue = record.getIntValue(CompositeDBAdapter.COMPOSITE_INTERNAL_ALIGNMENT_COL);
		return dbValue != UNALIGNED;
	}

	@Override
	public void setInternallyAligned(boolean aligned) {
		if (aligned == isInternallyAligned()) {
			return;
		}
		doSetInternallyAligned(aligned);
		adjustInternalAlignment(true);
		notifyAlignmentChanged();
	}

	protected void doSetInternallyAligned(boolean aligned) {
		lock.acquire();
		try {
			checkDeleted();
			if (aligned == isInternallyAligned()) {
				return;
			}
			int dbValue = aligned ? CompositeDB.ALIGNED_NO_PACKING : CompositeDB.UNALIGNED;
			record.setIntValue(CompositeDBAdapter.COMPOSITE_INTERNAL_ALIGNMENT_COL, dbValue);
			if (!aligned) {
				int dbExternalAlignment = CompositeDB.DEFAULT_ALIGNED;
				record.setIntValue(CompositeDBAdapter.COMPOSITE_EXTERNAL_ALIGNMENT_COL,
					dbExternalAlignment);
			}
			compositeAdapter.updateRecord(record, true);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	protected void setAlignment(Composite composite, boolean notify) {
		doSetInternallyAligned(composite.isInternallyAligned());

		doSetPackingValue(composite.getPackingValue());

		if (composite.isDefaultAligned()) {
			doSetToDefaultAlignment();
		}
		else if (composite.isMachineAligned()) {
			doSetToMachineAlignment();
		}
		else {
			doSetMinimumAlignment(composite.getMinimumAlignment());
		}
		adjustInternalAlignment(notify);
	}

	/**
	 * Adjusts the internal alignment of components within this composite based on
	 * the current settings of the internal alignment, packing, alignment type and
	 * minimum alignment value. This method should be called whenever any of the
	 * above settings are changed or whenever a components data type is changed or a
	 * component is added or removed.
	 * 
	 * @param notify
	 */
	protected abstract void adjustInternalAlignment(boolean notify);

	@Override
	public int getAlignment() {
		// TODO: use cached value if available (requires DB change to facilitate)
		return CompositeAlignmentHelper.getAlignment(getDataOrganization(), this);
	}

	/**
	 * Dump all components for use in {@link #toString()} representation.
	 * 
	 * @param buffer string buffer
	 * @param pad    padding to be used with each component output line
	 */
	protected void dumpComponents(StringBuilder buffer, String pad) {
		// limit output of filler components for unaligned structures
		DataTypeComponent[] components = getDefinedComponents();
		for (DataTypeComponent dtc : components) {
			DataType dataType = dtc.getDataType();
			buffer.append(pad + dtc.getOffset());
			buffer.append(pad + dataType.getName());
			if (dataType instanceof BitFieldDataType) {
				BitFieldDataType bfDt = (BitFieldDataType) dataType;
				buffer.append("(");
				buffer.append(Integer.toString(bfDt.getBitOffset()));
				buffer.append(")");
			}
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

	@Override
	public String toString() {
		StringBuilder stringBuffer = new StringBuilder();
		stringBuffer.append(getPathName() + "\n");
		stringBuffer.append(getAlignmentSettingsString() + "\n");
		stringBuffer.append(getTypeName() + " " + getDisplayName() + " {\n");
		dumpComponents(stringBuffer, "   ");
		stringBuffer.append("}\n");
		stringBuffer.append(
			"Size = " + getLength() + "   Actual Alignment = " + getAlignment() + "\n");
		return stringBuffer.toString();
	}

	private String getTypeName() {
		if (this instanceof Structure) {
			return "Structure";
		}
		else if (this instanceof Union) {
			return "Union";
		}
		return "";
	}

	private String getAlignmentSettingsString() {
		StringBuffer stringBuffer = new StringBuffer();
		if (!isInternallyAligned()) {
			stringBuffer.append("Unaligned");
		}
		else if (isDefaultAligned()) {
			stringBuffer.append("Aligned");
		}
		else if (isMachineAligned()) {
			stringBuffer.append("Machine aligned");
		}
		else {
			long alignment = getMinimumAlignment();
			stringBuffer.append("align(" + alignment + ")");
		}
		stringBuffer.append(getPackingString());
		return stringBuffer.toString();
	}

	private String getPackingString() {
		if (!isInternallyAligned()) {
			return "";
		}
		long packingValue = getPackingValue();
		if (packingValue == Composite.NOT_PACKING) {
			return "";
		}
		return " pack(" + packingValue + ")";
	}
}
