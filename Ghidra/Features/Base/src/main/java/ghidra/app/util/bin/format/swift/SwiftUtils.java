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
package ghidra.app.util.bin.format.swift;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Swift-related utility methods
 */
public class SwiftUtils {

	/**
	 * A {@link PointerTypedef pointer} to a relative 4-byte offset
	 */
	public static final PointerTypedef PTR_RELATIVE =
		new PointerTypedef(null, null, 4, null, PointerType.RELATIVE);

	/**
	 * A {@link PointerTypedef string pointer} to a 4-byte relative offset
	 */
	public static final PointerTypedef PTR_STRING =
		new PointerTypedef(null, StringDataType.dataType, 4, null, PointerType.RELATIVE);

	/**
	 * Checks if the given {@link Program} is a Swift program
	 * 
	 * @param program The {@link Program} to check
	 * @return True if the given {@link Program} is a Swift program; otherwise, false
	 */
	public static boolean isSwift(Program program) {
		List<String> prefixes = List.of("__swift", "swift", ".sw5");
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (prefixes.stream().anyMatch(prefix -> block.getName().startsWith(prefix))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the given {@List} of section names contains a Swift section name
	 * 
	 * @param sectionNames The {@link List} of section names to check
	 * @return True if the given {@List} of section names contains a Swift section name; otherwise, 
	 *   false
	 */
	public static boolean isSwift(List<String> sectionNames) {
		List<String> prefixes = List.of("__swift", "swift", ".sw5");
		for (String sectionName : sectionNames) {
			if (prefixes.stream().anyMatch(prefix -> sectionName.startsWith(prefix))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets a {@link List} of {@link MemoryBlock}s that match the given {@link SwiftSection}
	 * 
	 * @param section The {@link SwiftSection}
	 * @param program The {@link Program}
	 * @return A {@link List} of {@link MemoryBlock}s that match the given {@link SwiftSection}
	 */
	public static List<MemoryBlock> getSwiftBlocks(SwiftSection section, Program program) {
		List<MemoryBlock> result = new ArrayList<>();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			for (String sectionName : section.getSwiftSectionNames()) {
				if (block.getName().equals(sectionName)) {
					result.add(block);
					break;
				}
			}
		}
		return result;
	}

	/**
	 * Reads the integer at the current index and uses it as a relative pointer to read and
	 * return a string at that location.  When the read completes, the {@link BinaryReader} will
	 * be positioned directly after the initial relative pointer that was read.
	 *
	 * @param reader A {@link BinaryReader} positioned at the start of relative string pointer
	 * @return The read string
	 * @throws IOException if there was an IO-related problem during the reads
	 */
	public static String relativeString(BinaryReader reader) throws IOException {
		long fieldIndex = reader.getPointerIndex();
		int offset = reader.readNextInt();
		return reader.readAsciiString(fieldIndex + offset);
	}
}
