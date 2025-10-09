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
// Example analyzeHeadless prescript to set the DWARF analyzer's external debug files
// search location.
//
// Example:
//
//     export DWARF_EXTERNAL_DEBUG_FILES=/home/myuserid/debugfiles
//     analyzeHeadless [...] -preScript DWARFSetExternalDebugFilesLocationPrescript.java
//@category DWARF
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.dwarf.external.*;
import ghidra.util.Msg;

public class DWARFSetExternalDebugFilesLocationPrescript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String dwarfExtDebugFilesLocEnvVar = System.getenv("DWARF_EXTERNAL_DEBUG_FILES");
		if (dwarfExtDebugFilesLocEnvVar == null) {
			return;
		}
		File dir = new File(dwarfExtDebugFilesLocEnvVar);
		if (!dir.isDirectory()) {
			Msg.warn(this, "Invalid DWARF external debug files location specified: " + dir);
			return;
		}
		List<DebugInfoProvider> searchLocations = new ArrayList<>();

		File buildIdDir = new File(dir, ".build-id");
		if (buildIdDir.isDirectory()) {
			searchLocations.add(new BuildIdDebugFileProvider(buildIdDir));
		}
		searchLocations.add(new LocalDirDebugLinkProvider(dir));
		ExternalDebugFilesService edfs = new ExternalDebugFilesService(
			LocalDirDebugInfoDProvider.getGhidraCacheInstance(), searchLocations);
		ExternalDebugFilesService.saveToPrefs(edfs);
	}

}
