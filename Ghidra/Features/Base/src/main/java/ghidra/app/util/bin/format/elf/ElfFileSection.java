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
package ghidra.app.util.bin.format.elf;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.MemoryLoadable;

public interface ElfFileSection extends MemoryLoadable {
	
	/**
	 * Preferred memory address offset where data should be loaded.
	 * The returned offset will already have the prelink adjustment 
	 * applied, although will not reflect any change in the image base.
	 * @return default memory address offset where data should be loaded
	 */
	public long getVirtualAddress();

	/**
	 * Offset within file where section bytes are specified
	 * @return offset within file where section bytes are specified
	 */
	public long getFileOffset();

	/**
	 * Length of file section in bytes
	 * @return length of file section in bytes
	 */
	public long getFileSize();

	/**
	 * Length of memory section in bytes
	 * @return length of memory section in bytes
	 */
	default public long getMemorySize() {
		return getFileSize();
	}

	/**
	 * Size of each structured entry in bytes
	 * @return entry size or 0 if variable
	 */
	default public long getEntrySize() {
		return 0;
	}

	/**
	 * Binary reader for this file section
	 * @return Binary reader
	 */
	public BinaryReader getReader();

	/**
	 * Byte provider for this file section
	 * @return Byte provider
	 */
	default public ByteProvider getByteProvider() {
		return getReader().getByteProvider();
	}

	/**
	 * Create a subsection from this file section
	 * @param offset Offset of subsection from beginning of this file section
	 * @param size Length of subsection
	 * @return file subsection
	 */
	default public ElfFileSection subSection(long offset, long size) {
		return subSection(offset, size, getEntrySize());
	}

	/**
	 * Create a subsection from this file section
	 * @param offset Offset of subsection from beginning of this file section
	 * @param size Length of subsection
	 * @param entrySize Entry size for this subsection
	 * @return file subsection
	 */
	default public ElfFileSection subSection(long offset, long size, long entrySize) {
		if (offset == 0 && size == getMemorySize() && entrySize == getEntrySize()) {
			return this;
		}

		return new ElfFileSectionWrapper(this, offset, size, entrySize);
	}
}
