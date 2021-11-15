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
package ghidra.app.util.bin.format.dwarf4.external;

import java.io.IOException;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a collection of dwarf external debug files that can be searched. 
 */
public interface SearchLocation {
	/**
	 * Searchs for a debug file that fulfills the criteria specified in the {@link ExternalDebugInfo}.
	 *  
	 * @param debugInfo search criteria
	 * @param monitor {@link TaskMonitor}
	 * @return {@link FSRL} of the matching file, or {@code null} if not found
	 * @throws IOException if error
	 * @throws CancelledException if cancelled
	 */
	FSRL findDebugFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Returns the name of this instance, which should be a serialized copy of this instance.
	 * 
	 * @return String serialized data of this instance, typically in "something://serialized_data"
	 * form
	 */
	String getName();

	/**
	 * Returns a human formatted string describing this location, used in UI prompts or lists.
	 *  
	 * @return formatted string
	 */
	String getDescriptiveName();
}
