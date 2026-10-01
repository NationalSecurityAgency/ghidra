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
package ghidra.app.util.bin.format.dwarf.external;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Program;

/**
 * Metadata needed to find an ELF/DWARF external debug file, retrieved from an ELF binary's
 * ".gnu_debuglink" section and/or ".note.gnu.build-id" section.  
 * <p>
 * The debuglink can provide a filename and crc of the external debug file, while the build-id
 * can provide a hash that is converted to a filename that identifies the external debug file.
 */
public interface ExternalDebugInfo {

	/**
	 * Create a new {@link ExternalDebugInfo} from information found in the specified program.
	 *  
	 * @param program {@link Program} to query
	 * @return List of {@link ExternalDebugInfo} instances that were found in the program.
	 */
	public static List<ExternalDebugInfo> fromProgram(Program program) {
		List<ExternalDebugInfo> results = new ArrayList<>(2);

		BuildIdDebugInfo buildId = BuildIdDebugInfo.fromProgram(program);
		if (buildId != null) {
			results.add(buildId);
		}

		DebugLinkDebugInfo debugLink = DebugLinkDebugInfo.fromProgram(program);
		if (debugLink != null) {
			results.add(debugLink);
		}

		return results;
	}

}
