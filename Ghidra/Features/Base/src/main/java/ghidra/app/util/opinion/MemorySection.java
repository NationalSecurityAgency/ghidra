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
package ghidra.app.util.opinion;

import ghidra.app.util.bin.format.MemoryLoadable;
import ghidra.program.model.address.*;

class MemorySection {

	protected final MemoryLoadable key;

	// source data information
	protected final boolean isInitialized;
	protected final long fileOffset;
	protected final long length; // byte length of section
	protected final boolean isFragmentationOK;

	// destination information
	protected final AddressRange range;

	// metadata
	protected final String sectionName;
	protected final boolean isReadable;
	protected final boolean isWritable;
	protected final boolean isExecute;
	protected final String comment;

	/**
	 * Create memory "section" definition.  Those sections defined within the OTHER address
	 * space will be treated as non-loaded data.
	 * @param key the loadable section key which corresponds to this memory "section"
	 * @param isInitialized true if "section" will be initialized from a data source
	 * @param fileOffset data source offset (required if isInitialized is true)
	 * @param length number of bytes within this "section"
	 * @param range physical address range of "section" (i.e., not overlay addresses)
	 * @param sectionName section name
	 * @param isReadable true if "section" has read privilege
	 * @param isWritable true if "section" has write privilege
	 * @param isExecutable true if "section" has execute privilege
	 * @param comment section comment (used as basis for block comment)
	 * @param isFragmentationOK if true this memory section may be fragmented due to 
	 * conflict/overlap with other memory sections of higher precedence.
	 */
	MemorySection(MemoryLoadable key, boolean isInitialized, long fileOffset, long length,
			AddressRange range, String sectionName, boolean isReadable, boolean isWritable,
			boolean isExecute, String comment, boolean isFragmentationOK) {
		AddressSpace space = range.getAddressSpace();
		if (!space.isMemorySpace()) {
			throw new IllegalArgumentException("memory-based address required");
		}
		this.key = key;
		this.isInitialized = isInitialized;
		this.fileOffset = fileOffset;
		this.length = length;
		this.range = range;
		this.sectionName = sectionName;
		this.isReadable = isReadable;
		this.isWritable = isWritable;
		this.isExecute = isExecute;
		this.comment = comment;
		this.isFragmentationOK = isFragmentationOK;
	}

	public MemoryLoadable getKey() {
		return key;
	}

	public boolean isInitialized() {
		return isInitialized;
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public long getNumberOfBytes() {
		return length;
	}

	public AddressRange getRange() {
		return range;
	}

	public Address getMinAddress() {
		return range.getMinAddress();
	}

	public Address getMaxAddress() {
		return range.getMaxAddress();
	}

	public AddressSpace getAddressSpace() {
		return range.getMinAddress().getAddressSpace();
	}

	public String getSectionName() {
		return sectionName;
	}

	public boolean isLoaded() {
		return range.getAddressSpace() != AddressSpace.OTHER_SPACE;
	}

	public boolean isReadable() {
		return isReadable;
	}

	public boolean isWritable() {
		return isWritable;
	}

	public boolean isExecute() {
		return isExecute;
	}

	public String getComment() {
		return comment;
	}

	@Override
	public String toString() {
		return isInitialized
				? String.format("%s (%d, %d @ %s)", sectionName, fileOffset, length, range)
				: String.format("%s (uninitialized @ %s)", sectionName, range);
	}
}
