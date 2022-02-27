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
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.memory.TraceMemorySpaceInputStream;
import ghidra.util.MathUtilities;

public abstract class AbstractDBTraceProgramViewMemoryBlock implements MemoryBlock {

	private class MyMemoryBlockSourceInfo implements MemoryBlockSourceInfo {
		@Override
		public long getLength() {
			return getMemoryBlock().getSize();
		}

		@Override
		public Address getMinAddress() {
			return getMemoryBlock().getStart();
		}

		@Override
		public Address getMaxAddress() {
			return getMemoryBlock().getEnd();
		}

		@Override
		public String getDescription() {
			return getInfoDescription();
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
			return AbstractDBTraceProgramViewMemoryBlock.this;
		}

		@Override
		public boolean contains(Address address) {
			return getMemoryBlock().contains(address);
		}

		@Override
		public String toString() {
			return getDescription();
		}
	}

	protected final DBTraceProgramView program;
	private final List<MemoryBlockSourceInfo> info =
		Collections.singletonList(new MyMemoryBlockSourceInfo());

	protected AbstractDBTraceProgramViewMemoryBlock(DBTraceProgramView program) {
		this.program = program;
	}

	protected abstract String getInfoDescription();

	protected AddressSpace getAddressSpace() {
		return getStart().getAddressSpace();
	}

	protected DBTraceMemorySpace getMemorySpace() {
		return program.trace.getMemoryManager().getMemorySpace(getAddressSpace(), false);
	}

	protected AddressRange getAddressRange() {
		return new AddressRangeImpl(getStart(), getEnd());
	}

	@Override
	public int compareTo(MemoryBlock that) {
		return this.getStart().compareTo(that.getStart());
	}

	@Override
	public boolean contains(Address addr) {
		return getAddressRange().contains(addr);
	}

	@Override
	public long getSize() {
		return getEnd().subtract(getStart()) + 1;
	}

	@Override
	public BigInteger getSizeAsBigInteger() {
		return getEnd().getOffsetAsBigInteger()
				.subtract(getStart().getOffsetAsBigInteger())
				.add(BigInteger.ONE);
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
	public InputStream getData() {
		DBTraceMemorySpace ms = getMemorySpace();
		if (ms == null) {
			return null;
		}
		return new TraceMemorySpaceInputStream(program, ms, getAddressRange());
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
		AddressRange range = getAddressRange();
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
		AddressRange range = getAddressRange();
		if (!range.contains(addr)) {
			throw new MemoryAccessException();
		}
		DBTraceMemorySpace space =
			program.trace.getMemoryManager().getMemorySpace(range.getAddressSpace(), false);
		if (space == null) {
			throw new MemoryAccessException("Space does not exist");
		}
		len = MathUtilities.unsignedMin(len, range.getMaxAddress().subtract(addr) + 1);
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
		AddressRange range = getAddressRange();
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
		// TODO: What effect does this have? Does it makes sense for trace "overlays"?
		return getAddressSpace().isOverlaySpace();
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
