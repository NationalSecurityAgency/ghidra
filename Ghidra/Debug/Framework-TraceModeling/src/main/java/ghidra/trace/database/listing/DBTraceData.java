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
package ghidra.trace.database.listing;

import java.io.IOException;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.data.DBTraceDataSettingsOperations;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceData;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

/**
 * The implementation for a defined {@link TraceData} for {@link DBTrace}
 */
@DBAnnotatedObjectInfo(version = 0)
public class DBTraceData extends AbstractDBTraceCodeUnit<DBTraceData>
		implements DBTraceDefinedDataAdapter {
	private static final String TABLE_NAME = "Data";

	static final String PLATFORM_COLUMN_NAME = "Platform";
	static final String DATATYPE_COLUMN_NAME = "DataType";

	@DBAnnotatedColumn(PLATFORM_COLUMN_NAME)
	static DBObjectColumn PLATFORM_COLUMN;
	@DBAnnotatedColumn(DATATYPE_COLUMN_NAME)
	static DBObjectColumn DATATYPE_COLUMN;

	static String tableName(AddressSpace space, long threadKey, int frameLevel) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
	}

	@DBAnnotatedField(column = PLATFORM_COLUMN_NAME)
	private int platformKey;
	@DBAnnotatedField(column = DATATYPE_COLUMN_NAME)
	private long dataTypeID;

	protected InternalTracePlatform platform;
	protected DataType dataType;
	protected DataType baseDataType;
	protected Settings defaultSettings;

	protected AbstractDBTraceDataComponent[] componentCache = null;

	/**
	 * Construct a data unit
	 * 
	 * @param space the space
	 * @param tree the storage R*-Tree
	 * @param store the object store
	 * @param record the record
	 */
	public DBTraceData(DBTraceCodeSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceData, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(space, tree, store, record);
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		platform = space.manager.platformManager.getPlatformByKey(platformKey);
		if (platform == null) {
			throw new IOException("Data table is corrupt. Missing platform: " + platformKey);
		}
		dataType = space.dataTypeManager.getDataType(dataTypeID);
		if (dataType == null) {
			throw new IOException("Data table is corrupt. Missing datatype: " + dataTypeID);
		}
		baseDataType = getBaseDataType(dataType);
		final int dtLen = getDataTypeLength();
		if (dtLen != range.getLength() && dtLen != -1) {
			throw new IOException(
				"Data table is corrupt. Data unit and its datatype disagree on length.");
		}
		defaultSettings = dataType.getDefaultSettings();
	}

	@Override
	protected void setRecordValue(DBTraceData value) {
		// Nothing. Entry is the value
	}

	@Override
	protected DBTraceData getRecordValue() {
		return this;
	}

	/**
	 * Set the fields of this record
	 * 
	 * @param platform the platform
	 * @param dataType the data type
	 */
	protected void set(InternalTracePlatform platform, DataType dataType) {
		this.platformKey = platform.getIntKey();
		this.dataTypeID = space.dataTypeManager.getResolvedID(dataType);
		update(PLATFORM_COLUMN, DATATYPE_COLUMN);

		this.platform = platform;
		// Use the stored dataType, not the given one, in case it's different
		this.dataType = space.dataTypeManager.getDataType(dataTypeID);
		assert this.dataType != null;
		this.defaultSettings = this.dataType.getDefaultSettings();
		this.baseDataType = getBaseDataType(this.dataType);
	}

	/**
	 * If this unit's data type has a fixed length, get that length
	 * 
	 * @return the length, or -1
	 */
	protected int getDataTypeLength() {
		if (baseDataType instanceof Pointer) {
			// TODO: Also need to know where this address maps into the other language's spaces....
			// NOTE: Using default data space for now
			// TODO: I may not need this Pointer check, as clone(dtm) should adjust already
			return getLanguage().getDefaultDataSpace().getPointerSize();
		}
		return dataType.getLength(); // -1 is checked elsewhere
	}

	/**
	 * Get the base data type of the given data type, following typedefs recursively
	 * 
	 * @param dt the data type
	 * @return the base data type
	 */
	public static DataType getBaseDataType(DataType dt) {
		if (dt instanceof TypeDef) {
			return ((TypeDef) dt).getBaseDataType();
		}
		return dt;
	}

	@Override
	public TracePlatform getPlatform() {
		return platform;
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			space.dataMapSpace.deleteData(this);
		}
		space.definedData.unitRemoved(this);
	}

	@Override
	public void setEndSnap(long endSnap) {
		Range<Long> oldSpan;
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			oldSpan = getLifespan();
			super.setEndSnap(endSnap);
		}
		space.definedData.unitSpanChanged(oldSpan, this);
	}

	@Override
	public Language getLanguage() {
		return platform.getLanguage();
	}

	@Override
	public String toString() {
		return doToString();
	}

	@Override
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public DataType getBaseDataType() {
		return baseDataType;
	}

	@Override
	public DBTraceDefinedDataAdapter getParent() {
		return null;
	}

	@Override
	public DBTraceData getRoot() {
		return this;
	}

	@Override
	public int getRootOffset() {
		return 0;
	}

	@Override
	public int getParentOffset() {
		return 0;
	}

	@Override
	public AbstractDBTraceDataComponent[] doGetComponentCache() {
		// TODO: Can I just compute numComponents at construction?
		if (componentCache == null) {
			componentCache = new AbstractDBTraceDataComponent[getNumComponents()];
		}
		return componentCache;
	}

	@Override
	public int[] getComponentPath() {
		return EMPTY_INT_ARRAY;
	}

	@Override
	public int getComponentIndex() {
		return -1;
	}

	@Override
	public int getComponentLevel() {
		return 0;
	}

	@Override
	public String getFieldName() {
		return null;
	}

	@Override
	public String getPathName() {
		return getPrimarySymbolOrDynamicName();
	}

	@Override
	public String getComponentPathName() {
		return null;
	}

	@Override
	public StringBuilder getPathName(StringBuilder builder, boolean includeRootSymbol) {
		if (includeRootSymbol) {
			return builder.append(getPrimarySymbolOrDynamicName());
		}
		return builder;
	}

	@Override
	public DBTraceDataSettingsOperations getSettingsSpace(boolean createIfAbsent) {
		return (DBTraceDataSettingsOperations) getTrace().getDataSettingsAdapter()
				.get(space, createIfAbsent);
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}
}
