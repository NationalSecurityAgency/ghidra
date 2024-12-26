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
package ghidra.program.model.sourcemap;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * A SourceMapEntry consists of a {@link SourceFile}, a line number, a base address, 
 * and a length. If the length is positive, the base address and the length determine
 * an {@link AddressRange}. In this case, the length of a {@code SourceMapEntry} is the
 * length of the associated {@link AddressRange}, i.e., the number of {@link Address}es in 
 * the range (see {@link AddressRange#getLength()}).  The intent is that the range 
 * contains all of the bytes corresponding to a given line of source. The length of a
 * {@code SourceMapEntry} can be 0, in which case the associated range is null. Negative 
 * lengths are not allowed.
 * <p>
 * The baseAddress of a range must occur within a memory block of the program, as must each
 * address within the range of a {@code SourceMapEntry}.  A range may span multiple 
 * (contiguous) memory blocks.
 * <p>
 * If the ranges of two entries (with non-zero lengths) intersect, then the ranges must be
 * identical. The associated {@link SourceFile}s and/or line numbers can be different.
 * <p>
 * Entries with length zero do not conflict with other entries and may occur within the
 * range of another entry.
 * <p>
 * For a fixed source file, line number, base address, and length, there must be only one
 * SourceMapEntry.
 * <p>
 * SourceMapEntry objects are created using the {@link SourceFileManager} for a program, 
 * which must enforce the restrictions listed above.
 */
public interface SourceMapEntry extends Comparable<SourceMapEntry> {

	/**
	 * Returns the line number.
	 * @return line number
	 */
	public int getLineNumber();

	/**
	 * Returns the source file
	 * @return source file
	 */
	public SourceFile getSourceFile();

	/**
	 * Returns the base address of the entry
	 * @return base address
	 */
	public Address getBaseAddress();

	/**
	 * Returns the length of the range (number of addresses)
	 * @return length
	 */
	public long getLength();

	/**
	 * Returns the address range, or null for length 0 entries 
	 * @return address range or null
	 */
	public AddressRange getRange();

}
