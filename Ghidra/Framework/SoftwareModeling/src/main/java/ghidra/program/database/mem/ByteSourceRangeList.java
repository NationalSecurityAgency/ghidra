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

import java.util.*;

import ghidra.program.model.mem.MemoryBlock;

public class ByteSourceRangeList implements Iterable<ByteSourceRange> {
	List<ByteSourceRange> ranges;

	public ByteSourceRangeList(ByteSourceRange bsRange) {
		this();
		ranges.add(bsRange);
	}

	public ByteSourceRangeList() {
		ranges = new ArrayList<>();
	}

	@Override
	public Iterator<ByteSourceRange> iterator() {
		return ranges.iterator();
	}

	public void add(ByteSourceRange range) {
		if (range != null) {
			ranges.add(range);
		}
	}

	public void add(ByteSourceRangeList byteSourceList) {
		ranges.addAll(byteSourceList.ranges);
	}

	public int getRangeCount() {
		return ranges.size();
	}

	public ByteSourceRange get(int i) {
		return ranges.get(i);
	}

	public boolean isEmpty() {
		return ranges.isEmpty();
	}

	public Set<MemoryBlock> getOverlappingBlocks() {
		List<BlockRangeEntry> entries = new ArrayList<>();
		for (ByteSourceRange range : ranges) {
			entries.add(new BlockRangeStart(this, range));
			entries.add(new BlockRangeEnd(this, range));
		}
		Collections.sort(entries);
		return findOverlappingBlocks(entries);
	}

	public ByteSourceRangeList intersect(ByteSourceRangeList rangeList) {
		List<BlockRangeEntry> entries = new ArrayList<>();
		for (ByteSourceRange range : ranges) {
			entries.add(new BlockRangeStart(this, range));
			entries.add(new BlockRangeEnd(this, range));
		}
		for (ByteSourceRange range : rangeList) {
			entries.add(new BlockRangeStart(rangeList, range));
			entries.add(new BlockRangeEnd(rangeList, range));
		}
		Collections.sort(entries);
		return getIntersectingRanges(entries);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((ranges == null) ? 0 : ranges.hashCode());
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
		ByteSourceRangeList other = (ByteSourceRangeList) obj;
		if (ranges == null) {
			if (other.ranges != null) {
				return false;
			}
		}
		else if (!ranges.equals(other.ranges)) {
			return false;
		}
		return true;
	}

	private ByteSourceRangeList getIntersectingRanges(List<BlockRangeEntry> entries) {
		ByteSourceRangeList result = new ByteSourceRangeList();

		Set<ByteSourceRange> currentSet = new HashSet<>();

		for (BlockRangeEntry entry : entries) {
			if (entry.isStart()) {
				currentSet.add(entry.range);
			}
			else {
				currentSet.remove(entry.range);
				addIntersections(result, entry, currentSet);
			}
		}

		return result;
	}

	private void addIntersections(ByteSourceRangeList set, BlockRangeEntry entry,
			Set<ByteSourceRange> currentSet) {

		if (currentSet.isEmpty()) {
			return;
		}
		for (ByteSourceRange byteSourceRange : currentSet) {
			if (entry.owner == this) {
				set.add(entry.range.intersect(byteSourceRange));
			}
			else {
				set.add(byteSourceRange.intersect(entry.range));
			}
		}
	}

	private Set<MemoryBlock> findOverlappingBlocks(List<BlockRangeEntry> entries) {
		Set<MemoryBlock> overlappingBlocks = new HashSet<>();
		Set<ByteSourceRange> currentSet = new HashSet<>();

		for (BlockRangeEntry entry : entries) {
			if (entry.isStart()) {
				currentSet.add(entry.range);
			}
			else {
				currentSet.remove(entry.range);
				if (!currentSet.isEmpty()) {
					overlappingBlocks.add(entry.range.block);
					for (ByteSourceRange byteSourceRange : currentSet) {
						overlappingBlocks.add(byteSourceRange.block);
					}
				}
			}
		}
		return overlappingBlocks;
	}

	abstract class BlockRangeEntry implements Comparable<BlockRangeEntry> {
		private ByteSourceRange range;
		private long sourceId;
		private long offset;
		private ByteSourceRangeList owner;

		BlockRangeEntry(ByteSourceRangeList owner, ByteSourceRange range, long offset) {
			this.owner = owner;
			this.range = range;
			this.offset = offset;
			this.sourceId = range.getSourceId();
		}

		abstract boolean isStart();

		@Override
		public int compareTo(BlockRangeEntry o) {
			if (sourceId != o.sourceId) {
				return sourceId > o.sourceId ? 1 : -1;
			}
			if (offset == o.offset) {
				return (isStart() == o.isStart()) ? 0 : (isStart() ? -1 : 1);
			}
			return offset > o.offset ? 1 : -1;
		}
	}

	class BlockRangeStart extends BlockRangeEntry {
		BlockRangeStart(ByteSourceRangeList owner, ByteSourceRange range) {
			super(owner, range, range.getOffset());
		}
		@Override
		boolean isStart() {
			return true;
		}

	}

	class BlockRangeEnd extends BlockRangeEntry {
		BlockRangeEnd(ByteSourceRangeList owner, ByteSourceRange range) {
			super(owner, range, range.getOffset() + range.size - 1);
		}

		@Override
		boolean isStart() {
			return false;
		}

	}
}
