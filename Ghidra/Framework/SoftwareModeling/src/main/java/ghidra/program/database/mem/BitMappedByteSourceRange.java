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

public class BitMappedByteSourceRange extends ByteSourceRange {

	public BitMappedByteSourceRange(MemoryBlock block, Address start, long sourceId, long offset,
			long size) {

		super(block, start, size, sourceId, offset);
	}

	@Override
	public Address getEnd() {
		return getStart().add(size * 8 - 1);
	}

	@Override
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
		long sourceSize = minEndOffset - maxOffset + 1;
		return new BitMappedByteSourceRange(block, start.add((maxOffset - byteSourceOffset) / 8),
			sourceId, maxOffset, sourceSize);
	}
}
