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

import java.nio.ByteBuffer;

import com.google.common.collect.Range;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.data.DBTraceDataSettingsAdapter.DBTraceDataSettingsSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;

public abstract class AbstractDBTraceDataComponent implements DBTraceDefinedDataAdapter {

	protected final DBTraceData root;
	protected final DBTraceDefinedDataAdapter parent;
	protected final int index;
	protected final Address address;
	protected final DataType dataType;
	protected final int length;

	protected final int level;
	protected final DataType baseDataType;
	protected final Address maxAddress;
	protected final Settings defaultSettings;

	protected int[] path;

	protected AbstractDBTraceDataComponent[] componentCache = null;

	public AbstractDBTraceDataComponent(DBTraceData root, DBTraceDefinedDataAdapter parent,
			int index, Address address, DataType dataType, int length) {
		this.root = root;
		this.parent = parent;
		this.index = index;
		this.address = address;
		this.dataType = dataType;
		this.length = length;

		this.level = parent.getComponentLevel() + 1;
		this.baseDataType = DBTraceData.getBaseDataType(dataType);
		// NOTE: Max address of root will have already overflowed if that were a concern here
		this.maxAddress = address.add(length - 1);
		this.defaultSettings = dataType.getDefaultSettings();
	}

	@Override
	public String toString() {
		return doToString();
	}

	@Override
	public void delete() {
		throw new UnsupportedOperationException("Either delete the root, or modify the type");
	}

	@Override
	public DBTrace getTrace() {
		return root.getTrace();
	}

	@Override
	public TraceThread getThread() {
		return root.getThread();
	}

	@Override
	public Language getLanguage() {
		return root.getLanguage();
	}

	@Override
	public Range<Long> getLifespan() {
		return root.getLifespan();
	}

	@Override
	public long getStartSnap() {
		return root.getStartSnap();
	}

	@Override
	public void setEndSnap(long endSnap) {
		throw new UnsupportedOperationException("Set end-snap of root unit");
	}

	@Override
	public long getEndSnap() {
		return root.getEndSnap();
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public Address getMaxAddress() {
		return maxAddress;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public int getBytes(ByteBuffer buffer, int addressOffset) {
		int componentOffset = (int) address.subtract(root.getAddress());
		return root.getBytes(buffer, addressOffset + componentOffset);
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
	public DataType getDataType() {
		return dataType;
	}

	@Override
	public DataType getBaseDataType() {
		return baseDataType;
	}

	@Override
	public int[] getComponentPath() {
		try (LockHold hold = LockHold.lock(root.space.lock.writeLock())) {
			if (path != null) {
				return path;
			}
			path = new int[level];
			DBTraceDefinedDataAdapter a = this;
			for (int i = level - 1; i >= 0; i--) {
				path[i] = a.getComponentIndex();
				a = a.getParent();
			}
			assert a.getRoot() == a;
			return path;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * In other words, this includes the symbol name of the root unit; whereas,
	 * {@link #getComponentPathName()} omits it.
	 */
	@Override
	public String getPathName() {
		return getPathName(new StringBuilder(), true).toString();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * In other words, this omits the symbol name of the root unit; whereas, {@link #getPathName()}
	 * includes it.
	 */
	@Override
	public String getComponentPathName() {
		return getPathName(new StringBuilder(), false).toString();
	}

	public abstract String getFieldSyntax();

	@Override
	public StringBuilder getPathName(StringBuilder builder, boolean includeRootSymbol) {
		return parent.getPathName(builder, includeRootSymbol).append(getFieldSyntax());
	}

	@Override
	public DBTraceDefinedDataAdapter getParent() {
		return parent;
	}

	@Override
	public DBTraceData getRoot() {
		return root;
	}

	@Override
	public int getRootOffset() {
		return (int) address.subtract(root.getAddress());
	}

	@Override
	public int getParentOffset() {
		return (int) address.subtract(parent.getAddress());
	}

	@Override
	public int getComponentIndex() {
		return index;
	}

	@Override
	public int getComponentLevel() {
		return level;
	}

	@Override
	public DBTraceDataSettingsSpace getSettingsSpace(boolean createIfAbsent) {
		return root.getSettingsSpace(createIfAbsent);
	}

	@Override
	public Settings getDefaultSettings() {
		return defaultSettings;
	}
}
