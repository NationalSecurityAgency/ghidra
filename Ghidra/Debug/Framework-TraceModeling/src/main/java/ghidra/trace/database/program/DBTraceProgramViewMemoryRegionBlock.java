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
package ghidra.trace.database.program;

import java.io.InputStream;
import java.math.BigInteger;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.memory.*;

// TODO: Proper locking all over here
public class DBTraceProgramViewMemoryRegionBlock extends AbstractDBTraceProgramViewMemoryBlock {

	private final TraceMemoryRegion region;

	public DBTraceProgramViewMemoryRegionBlock(DBTraceProgramView program,
			TraceMemoryRegion region) {
		super(program);
		this.region = region;
	}

	@Override
	protected String getInfoDescription() {
		return "Trace region: " + region;
	}

	@Override
	protected AddressSpace getAddressSpace() {
		return region.getRange().getAddressSpace();
	}

	@Override
	protected AddressRange getAddressRange() {
		return region.getRange();
	}

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		region.setRead(read);
		region.setWrite(write);
		region.setExecute(execute);
	}

	@Override
	public int getPermissions() {
		int bits = 0;
		for (TraceMemoryFlag flag : region.getFlags()) {
			bits |= flag.getBits();
		}
		return bits;
	}

	@Override
	public InputStream getData() {
		AddressRange range = region.getRange();
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), false);
		if (space == null) {
			return null;
		}
		return new TraceMemorySpaceInputStream(program, space, range);
	}

	@Override
	public Address getStart() {
		return region.getRange().getMinAddress();
	}

	@Override
	public Address getEnd() {
		return region.getRange().getMaxAddress();
	}

	@Override
	public long getSize() {
		return region.getRange().getLength();
	}

	@Override
	public BigInteger getSizeAsBigInteger() {
		return region.getRange().getBigLength();
	}

	@Override
	public String getName() {
		return region.getName();
	}

	@Override
	public void setName(String name) throws LockException {
		region.setName(name);
	}

	@Override
	public boolean isRead() {
		return region.isRead();
	}

	@Override
	public void setRead(boolean r) {
		region.setRead(r);
	}

	@Override
	public boolean isWrite() {
		return region.isWrite();
	}

	@Override
	public void setWrite(boolean w) {
		region.setWrite(w);
	}

	@Override
	public boolean isExecute() {
		return region.isExecute();
	}

	@Override
	public void setExecute(boolean e) {
		region.setExecute(e);
	}

	@Override
	public boolean isVolatile() {
		return region.isVolatile();
	}

	@Override
	public void setVolatile(boolean v) {
		region.setVolatile(v);
	}
}
