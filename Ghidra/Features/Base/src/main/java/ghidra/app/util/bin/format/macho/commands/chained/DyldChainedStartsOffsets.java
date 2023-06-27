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
package ghidra.app.util.bin.format.macho.commands.chained;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.macho.MachConstants;
import ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a dyld_chained_starts_offsets structure.
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h">mach-o/fixup-chains.h</a> 
 */
public class DyldChainedStartsOffsets implements StructConverter {

	private int pointerFormat;
	private int startsCount;
	private int[] chainStarts;

	/**
	 * Creates a new {@link DyldChainedStartsOffsets}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the structure
	 * @throws IOException if there was an IO-related problem creating the structure
	 */
	public DyldChainedStartsOffsets(BinaryReader reader) throws IOException {
		pointerFormat = reader.readNextInt();
		startsCount = reader.readNextInt();
		chainStarts = reader.readNextIntArray(startsCount);
	}

	/**
	 * Gets the pointer format
	 * 
	 * @return The pointer format
	 */
	public DyldChainType getPointerFormat() {
		return DyldChainType.lookupChainPtr(pointerFormat);
	}

	/**
	 * Gets the starts count
	 * 
	 * @return The starts count
	 */
	public int getStartsCount() {
		return startsCount;
	}

	/**
	 * Gets the chain start offsets
	 * 
	 * @return The chain start offsets
	 */
	public int[] getChainStartOffsets() {
		return chainStarts;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("dyld_chained_starts_offset", 0);
		struct.add(DWORD, "pointer_format", "DYLD_CHAINED_PTR_*");
		struct.add(DWORD, "starts_count", "number of starts in array");
		struct.add(new ArrayDataType(IBO32, startsCount, 1), "chain_starts",
			"array chain start offsets");
		struct.setCategoryPath(new CategoryPath(MachConstants.DATA_TYPE_CATEGORY));
		return struct;
	}
}
