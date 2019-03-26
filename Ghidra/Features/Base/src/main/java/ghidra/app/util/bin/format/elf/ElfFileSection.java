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

import ghidra.app.util.bin.StructConverter;

public interface ElfFileSection extends StructConverter {
	
	/**
	 * Preferred memory address offset where data should be loaded.
	 * The returned offset will already have the prelink adjustment 
	 * applied, although will not reflect any change in the image base.
	 * @return default memory address offset where data should be loaded
	 */
	public long getAddressOffset();

	/**
	 * Offset within file where section bytes are specified
	 * @return offset within file where section bytes are specified
	 */
	public long getFileOffset();

	/**
	 * Length of file section in bytes
	 * @return length of file section in bytes
	 */
	public long getLength();
	
	/**
	 * Size of each structured entry in bytes
	 * @return entry size or -1 if variable
	 */
	public int getEntrySize();

}
