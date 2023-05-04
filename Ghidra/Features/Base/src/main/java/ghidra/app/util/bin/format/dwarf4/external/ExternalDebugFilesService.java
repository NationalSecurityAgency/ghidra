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
import java.util.List;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A collection of {@link SearchLocation search locations} that can be queried to find a
 * DWARF external debug file, which is a second ELF binary that contains the debug information
 * that was stripped from the original ELF binary.
 */
public class ExternalDebugFilesService {
	private List<SearchLocation> searchLocations;

	/**
	 * Creates a new instance using the list of search locations.
	 * 
	 * @param searchLocations list of {@link SearchLocation search locations}
	 */
	public ExternalDebugFilesService(List<SearchLocation> searchLocations) {
		this.searchLocations = searchLocations;
	}

	/**
	 * Returns the configured search locations.
	 * 
	 * @return list of search locations
	 */
	public List<SearchLocation> getSearchLocations() {
		return searchLocations;
	}

	/**
	 * Searches for the specified external debug file.
	 * <p>
	 * Returns the FSRL of a matching file, or null if not found.
	 * 
	 * @param debugInfo information about the external debug file
	 * @param monitor {@link TaskMonitor}
	 * @return {@link FSRL} of found file, or {@code null} if not found
	 * @throws IOException if error
	 */
	public FSRL findDebugFile(ExternalDebugInfo debugInfo, TaskMonitor monitor)
			throws IOException {
		try {
			for (SearchLocation searchLoc : searchLocations) {
				monitor.checkCancelled();
				FSRL result = searchLoc.findDebugFile(debugInfo, monitor);
				if (result != null) {
					return result;
				}
			}
		}
		catch (CancelledException ce) {
			// fall thru, return null
		}
		return null;
	}

}
