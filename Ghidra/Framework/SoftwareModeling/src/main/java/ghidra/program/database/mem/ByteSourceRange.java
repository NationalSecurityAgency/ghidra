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
package ghidra.program.database.mem;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class ByteSourceRange {
	protected final Address start;
	protected final long size;
	protected final long sourceId;
	protected final long byteSourceOffset;
	protected MemoryBlock block;

	public ByteSourceRange(MemoryBlock block, Address start, long size, long sourceId,
			long offset) {
		this.block = block;
		this.start = start;
		this.size = size;
		this.sourceId = sourceId;
		this.byteSourceOffset = offset;
	}

	public Address getStart() {
		return start;
	}

	public Address getEnd() {
		return start.add(size - 1);
	}

	public long getSize() {
		return size;
	}

	public long getSourceId() {
		return sourceId;
	}

	public long getOffset() {
		return byteSourceOffset;
	}

	public ByteSourceRange intersect(ByteSourceRange range) {
		if (sourceId != range.sourceId) {
			return null;
		}
		long maxOffset = Math.max(byteSourceOffset, range.byteSourceOffset);
		long minEndOffset =
			Math.min(byteSourceOffset + size - 1, range.byteSourceOffset + range.size - 1);
		if (maxOffset > minEndOffset) {
			return null;
		}
		return new ByteSourceRange(block, start.add(maxOffset - byteSourceOffset),
			minEndOffset - maxOffset + 1, sourceId, maxOffset);
	}

	public MemoryBlock getMemoryBlock() {
		return block;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (byteSourceOffset ^ (byteSourceOffset >>> 32));
		result = prime * result + (int) (size ^ (size >>> 32));
		result = prime * result + (int) (sourceId ^ (sourceId >>> 32));
		result = prime * result + ((start == null) ? 0 : start.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ByteSourceRange other = (ByteSourceRange) obj;
		if (block == null) {
			if (other.block != null) {
				return false;
			}
		}
		else if (!block.equals(other.block)) {
			return false;
		}
		if (byteSourceOffset != other.byteSourceOffset) {
			return false;
		}
		if (size != other.size) {
			return false;
		}
		if (sourceId != other.sourceId) {
			return false;
		}
		if (start == null) {
			if (other.start != null) {
				return false;
			}
		}
		else if (!start.equals(other.start)) {
			return false;
		}
		return true;
	}

}
