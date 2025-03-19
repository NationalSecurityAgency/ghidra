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

import javax.help.UnsupportedOperationException;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.*;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.memory.*;

// TODO: Proper locking all over here
public class DBTraceProgramViewMemoryRegionBlock extends AbstractDBTraceProgramViewMemoryBlock {

	private final TraceMemoryRegion region;
	private final long snap; // Snap may be in viewport, not current

	public DBTraceProgramViewMemoryRegionBlock(DBTraceProgramView program,
			TraceMemoryRegion region, long snap) {
		super(program);
		this.region = region;
		this.snap = snap;
	}

	@Override
	protected String getInfoDescription() {
		return "Trace region: " + region;
	}

	@Override
	protected AddressSpace getAddressSpace() {
		return region.getRange(snap).getAddressSpace();
	}

	@Override
	public AddressRange getAddressRange() {
		return region.getRange(snap);
	}

	protected void checkSnapOnSet() {
		long snap = program.getSnap();
		if (snap != this.snap) {
			/**
			 * TODO: Copy the region to here? It would immediately invalidate this block, but I
			 * suppose that's okay, as long as the UI updates appropriately.
			 */
			throw new UnsupportedOperationException("Region is from a forked snapshot");
		}
	}

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		checkSnapOnSet();
		region.setRead(snap, read);
		region.setWrite(snap, write);
		region.setExecute(snap, execute);
	}

	@Override
	public int getFlags() {
		int bits = 0;
		for (TraceMemoryFlag flag : region.getFlags(snap)) {
			bits |= flag.getBits();
		}
		return bits;
	}

	@Override
	public InputStream getData() {
		AddressRange range = region.getRange(snap);
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), false);
		if (space == null) {
			return null;
		}
		return new TraceMemorySpaceInputStream(program, space, range);
	}

	@Override
	public Address getStart() {
		return region.getRange(snap).getMinAddress();
	}

	@Override
	public Address getEnd() {
		return region.getRange(snap).getMaxAddress();
	}

	@Override
	public long getSize() {
		return region.getRange(snap).getLength();
	}

	@Override
	public BigInteger getSizeAsBigInteger() {
		return region.getRange(snap).getBigLength();
	}

	@Override
	public String getName() {
		return region.getName(snap);
	}

	@Override
	public void setName(String name) throws LockException {
		checkSnapOnSet();
		region.setName(snap, name);
	}

	@Override
	public boolean isRead() {
		return region.isRead(snap);
	}

	@Override
	public void setRead(boolean r) {
		checkSnapOnSet();
		region.setRead(snap, r);
	}

	@Override
	public boolean isWrite() {
		return region.isWrite(snap);
	}

	@Override
	public void setWrite(boolean w) {
		checkSnapOnSet();
		region.setWrite(snap, w);
	}

	@Override
	public boolean isExecute() {
		return region.isExecute(snap);
	}

	@Override
	public void setExecute(boolean e) {
		checkSnapOnSet();
		region.setExecute(snap, e);
	}

	@Override
	public boolean isVolatile() {
		return region.isVolatile(snap);
	}

	@Override
	public void setVolatile(boolean v) {
		checkSnapOnSet();
		region.setVolatile(snap, v);
	}

	@Override
	public boolean isArtificial() {
		// By definition, any region present on target is non-artificial
		return false;
	}

	@Override
	public void setArtificial(boolean a) {
		throw new UnsupportedOperationException();
	}
}
