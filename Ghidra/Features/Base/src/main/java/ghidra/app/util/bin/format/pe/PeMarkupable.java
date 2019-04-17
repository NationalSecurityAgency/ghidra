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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Common interface for standardizing the markup of a PE structure.
 */
public interface PeMarkupable {

	/**
	 * Marks up a PE structure.
	 * 
	 * @param program The program to markup.
	 * @param isBinary True if the program is binary; otherwise, false.
	 * @param monitor The monitor.
	 * @param log The log.
	 * @param ntHeader The PE's NT Header structure.
	 * @throws DuplicateNameException
	 * @throws CodeUnitInsertionException
	 * @throws IOException
	 * @throws MemoryAccessException
	 */
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException;
}
