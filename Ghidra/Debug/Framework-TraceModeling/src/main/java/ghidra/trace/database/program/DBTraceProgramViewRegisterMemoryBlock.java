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

import javax.help.UnsupportedOperationException;

import ghidra.framework.store.LockException;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.DBTraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemorySpaceInputStream;

public class DBTraceProgramViewRegisterMemoryBlock implements MemoryBlock {
	public static final String REGS_BLOCK_NAME = "regs";

	private class DBTraceProgramViewRegisterMemoryBlockSourceInfo implements MemoryBlockSourceInfo {
		@Override
		public long getLength() {
			return range.getLength();
		}

		@Override
		public Address getMinAddress() {
			return range.getMinAddress();
		}

		@Override
		public Address getMaxAddress() {
			return range.getMaxAddress();
		}

		@Override
		public String getDescription() {
			return "Trace registers: " + space.getThread().getName();
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
			return DBTraceProgramViewRegisterMemoryBlock.this;
		}

		@Override
		public boolean contains(Address address) {
			return range.contains(address);
		}

		@Override
		public String toString() {
			return getDescription();
		}
	}

	private final DBTraceProgramView program;
	private final DBTraceMemoryRegisterSpace space;
	private final AddressRange range;

	private final List<MemoryBlockSourceInfo> info =
		Collections.singletonList(new DBTraceProgramViewRegisterMemoryBlockSourceInfo());

	public DBTraceProgramViewRegisterMemoryBlock(DBTraceProgramView program,
			DBTraceMemoryRegisterSpace space) {
		this.program = program;
		this.space = space;
		this.range = new AddressRangeImpl(space.getAddressSpace().getMinAddress(),
			space.getAddressSpace().getMaxAddress());
	}

	@Override
	public int compareTo(MemoryBlock that) {
		return this.getStart().compareTo(that.getStart());
	}

	@Override
	public int getPermissions() {
		return MemoryBlock.READ | MemoryBlock.WRITE;
	}

	@Override
	public InputStream getData() {
		return new TraceMemorySpaceInputStream(program, space, range);
	}

	@Override
	public boolean contains(Address addr) {
		return range.contains(addr);
	}

	@Override
	public Address getStart() {
		return range.getMinAddress();
	}

	@Override
	public Address getEnd() {
		return range.getMaxAddress();
	}

	@Override
	public long getSize() {
		return range.getLength();
	}

	@Override
	public String getName() {
		return REGS_BLOCK_NAME;
	}

	@Override
	public void setName(String name) throws IllegalArgumentException, LockException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getComment() {
		return null;
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isRead() {
		return true;
	}

	@Override
	public void setRead(boolean r) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isWrite() {
		return true;
	}

	@Override
	public void setWrite(boolean w) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExecute() {
		return false;
	}

	@Override
	public void setExecute(boolean e) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPermissions(boolean read, boolean write, boolean execute) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isVolatile() {
		return false;
	}

	@Override
	public void setVolatile(boolean v) {
		throw new UnsupportedOperationException();
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
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
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
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
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
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
		}
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
