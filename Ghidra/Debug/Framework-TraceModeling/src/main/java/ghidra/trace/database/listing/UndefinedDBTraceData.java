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
import java.util.Collections;
import java.util.List;

import com.google.common.collect.Range;

import ghidra.docking.settings.Settings;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.data.DBTraceDataSettingsOperations;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.util.TraceAddressSpace;

public class UndefinedDBTraceData implements DBTraceDataAdapter, DBTraceSpaceKey {
	protected final DBTrace trace;
	protected final long snap;
	protected final Range<Long> lifespan;
	protected final Address address;
	protected final DBTraceThread thread;
	protected final int frameLevel;

	public UndefinedDBTraceData(DBTrace trace, long snap, Address address, DBTraceThread thread,
			int frameLevel) {
		this.trace = trace;
		this.snap = snap;
		this.lifespan = DBTraceUtils.toRange(snap, snap);
		this.address = address;
		this.thread = thread;
		this.frameLevel = frameLevel;
	}

	@Override
	public TraceAddressSpace getTraceSpace() {
		return this;
	}

	@Override
	public AddressSpace getAddressSpace() {
		return address.getAddressSpace();
	}

	@Override
	public void delete() {
		throw new UnsupportedOperationException("Cannot delete an undefined code unit");
	}

	@Override
	public DBTrace getTrace() {
		return trace;
	}

	@Override
	public Language getLanguage() {
		return trace.getBaseLanguage();
	}

	@Override
	public AddressRange getRange() {
		// TODO: Cache this?
		return new AddressRangeImpl(getMinAddress(), getMaxAddress());
	}

	@Override
	public TraceAddressSnapRange getBounds() {
		// TODO: Cache this?
		return new ImmutableTraceAddressSnapRange(getMinAddress(), getMaxAddress(), getLifespan());
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public long getStartSnap() {
		return snap;
	}

	@Override
	public void setEndSnap(long endSnap) {
		throw new UnsupportedOperationException("Cannot modify lifespan of default data unit");
	}

	@Override
	public long getEndSnap() {
		return snap;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public DBTraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}

	@Override
	public int getLength() {
		return 1;
	}

	@Override
	public Address getMaxAddress() {
		return address;
	}

	@Override
	public String toString() {
		return doToString();
	}

	@Override
	public Address getAddress(int opIndex) {
		// I should think an undefined data unit never presents an address, or operand
		// for that matter....
		return null;
	}

	@Override
	public int getBytes(ByteBuffer buffer, int addressOffset) {
		DBTraceMemorySpace mem = trace.getMemoryManager().get(this, false);
		if (mem == null) {
			// TODO: 0-fill instead? Will need to check memory space bounds.
			return 0;
		}
		return mem.getBytes(getStartSnap(), address.add(addressOffset), buffer);
	}

	@Override
	public boolean isDefined() {
		return false;
	}

	@Override
	public DataType getDataType() {
		return DataType.DEFAULT;
	}

	@Override
	public DataType getBaseDataType() {
		return DataType.DEFAULT;
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
	public Data getParent() {
		return null;
	}

	@Override
	public DBTraceDataAdapter getRoot() {
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
	public TraceData getComponent(int index) {
		return null;
	}

	@Override
	public TraceData getComponent(int[] componentPath) {
		if (componentPath == null || componentPath.length == 0) {
			return this;
		}
		return null;
	}

	@Override
	public int[] getComponentPath() {
		return EMPTY_INT_ARRAY;
	}

	@Override
	public int getNumComponents() {
		return 0;
	}

	@Override
	public TraceData getComponentAt(int offset) {
		return null;
	}

	@Override
	public Data getComponentContaining(int offset) {
		return null;
	}

	@Override
	public List<Data> getComponentsContaining(int offset) {
		if (offset < 0 || offset >= getLength()) {
			return null;
		}
		return Collections.emptyList();
	}

	@Override
	public UndefinedDBTraceData getPrimitiveAt(int offset) {
		if (offset < 0 || offset >= getLength()) {
			return null;
		}
		return this;
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
	public DBTraceDataSettingsOperations getSettingsSpace(boolean createIfAbsent) {
		return getTrace().getDataSettingsAdapter().get(this, createIfAbsent);
	}

	@Override
	public Settings getDefaultSettings() {
		return DataType.DEFAULT.getDefaultSettings();
	}
}
