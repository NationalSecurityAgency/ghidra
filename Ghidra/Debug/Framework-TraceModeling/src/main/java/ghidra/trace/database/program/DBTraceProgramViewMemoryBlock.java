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
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemorySpaceInputStream;

// TODO: Proper locking all over here
public class DBTraceProgramViewMemoryBlock implements MemoryBlock {

	private class DBTraceProgramViewMemoryBlockSourceInfo implements MemoryBlockSourceInfo {
		@Override
		public long getLength() {
			return region.getLength();
		}

		@Override
		public Address getMinAddress() {
			return region.getMinAddress();
		}

		@Override
		public Address getMaxAddress() {
			return region.getMaxAddress();
		}

		@Override
		public String getDescription() {
			return "Trace region: " + region;
		}

		@Override
		public Optional<FileBytes> getFileBytes() {
			return Optional.empty();
		}

		@Override
		public long getFileBytesOffset() {
			return -1;
		}

		@Override
		public long getFileBytesOffset(Address address) {
			return -1;
		}

		@Override
		public Optional<AddressRange> getMappedRange() {
			return Optional.empty();
		}

		@Override
		public Optional<ByteMappingScheme> getByteMappingScheme() {
			return Optional.empty();
		}

		@Override
		public MemoryBlock getMemoryBlock() {
			return DBTraceProgramViewMemoryBlock.this;
		}

		@Override
		public boolean contains(Address address) {
			return region.getRange().contains(address);
		}

		@Override
		public String toString() {
			return getDescription();
		}
	}

	private final DBTraceProgramView program;
	private final DBTraceMemoryRegion region;

	private final List<MemoryBlockSourceInfo> info =
		Collections.singletonList(new DBTraceProgramViewMemoryBlockSourceInfo());

	public DBTraceProgramViewMemoryBlock(DBTraceProgramView program, DBTraceMemoryRegion region) {
		this.program = program;
		this.region = region;
	}

	@Override
	public int compareTo(MemoryBlock that) {
		return this.getStart().compareTo(that.getStart());
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
	public boolean contains(Address addr) {
		return region.getRange().contains(addr);
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
	public String getName() {
		return region.getName();
	}

	@Override
	public void setName(String name) throws LockException {
		region.setName(name);
	}

	@Override
	public String getComment() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setComment(String comment) {
		// TODO Auto-generated method stub
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

	@Override
	public String getSourceName() {
		return "Trace"; // TODO: What does this method actually do?
	}

	@Override
	public void setSourceName(String sourceName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public byte getByte(Address addr) throws MemoryAccessException {
		AddressRange range = region.getRange();
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
		}
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), false);
		if (space == null) {
			throw new MemoryAccessException("Space does not exist");
		}
		ByteBuffer buf = ByteBuffer.allocate(1);
		if (space.getViewBytes(program.snap, addr, buf) != 1) {
			throw new MemoryAccessException();
		}
		return buf.get(0);
	}

	@Override
	public int getBytes(Address addr, byte[] b) throws MemoryAccessException {
		return getBytes(addr, b, 0, b.length);
	}

	@Override
	public int getBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		AddressRange range = region.getRange();
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
		}
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), false);
		if (space == null) {
			throw new MemoryAccessException("Space does not exist");
		}
		len = (int) Math.min(len, range.getMaxAddress().subtract(addr) + 1);
		return space.getViewBytes(program.snap, addr, ByteBuffer.wrap(b, off, len));
	}

	@Override
	public void putByte(Address addr, byte b) throws MemoryAccessException {
		if (putBytes(addr, new byte[] { b }) != 1) {
			throw new MemoryAccessException();
		}
	}

	@Override
	public int putBytes(Address addr, byte[] b) throws MemoryAccessException {
		return putBytes(addr, b, 0, b.length);
	}

	@Override
	public int putBytes(Address addr, byte[] b, int off, int len) throws MemoryAccessException {
		AddressRange range = region.getRange();
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
		}
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), true);
		len = (int) Math.min(len, range.getMaxAddress().subtract(addr) + 1);
		return space.putBytes(program.snap, addr, ByteBuffer.wrap(b, off, len));
	}

	@Override
	public MemoryBlockType getType() {
		return MemoryBlockType.DEFAULT;
	}

	@Override
	public boolean isInitialized() {
		return true;
	}

	@Override
	public boolean isMapped() {
		return false;
	}

	@Override
	public boolean isOverlay() {
		return false;
	}

	@Override
	public boolean isLoaded() {
		return true;
	}

	@Override
	public List<MemoryBlockSourceInfo> getSourceInfos() {
		return info;
	}
}
