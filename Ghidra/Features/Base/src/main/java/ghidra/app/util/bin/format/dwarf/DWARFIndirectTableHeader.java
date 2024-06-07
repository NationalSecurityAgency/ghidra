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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Common base functionality of indirect table headers (DWARFAddressListHeader, 
 * DWARFLocationListHeader, etc)
 */
public abstract class DWARFIndirectTableHeader {

	protected final long startOffset;
	protected final long endOffset;
	protected final long firstElementOffset;

	public DWARFIndirectTableHeader(long startOffset, long endOffset, long firstElementOffset) {
		this.startOffset = startOffset;
		this.endOffset = endOffset;
		this.firstElementOffset = firstElementOffset;
	}

	public long getStartOffset() {
		return startOffset;
	}

	public long getFirstElementOffset() {
		return firstElementOffset;
	}

	public long getEndOffset() {
		return endOffset;
	}

	public abstract long getOffset(int index, BinaryReader reader) throws IOException;

}
