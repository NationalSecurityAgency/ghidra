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
//Separates co-mingled n-bit and 64-bit binaries into two folder trees. 
//@category Project
//@menupath

import java.io.IOException;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.util.InvalidNameException;

public class BatchSegregate64bit extends GhidraScript {

	public BatchSegregate64bit() {
	}

	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder32 =
			askProjectFolder("Choose root folder to recursively 'segregate'");
		DomainFolder projRoot = rootFolder32.getProjectData().getRootFolder();
		String rootFolder32Str = rootFolder32.getPathname() + "/";
		String rootFolder64Str = rootFolder32.getPathname() + "-x64/";

		long start_ts = System.currentTimeMillis();
		monitor.initialize(0);
		monitor.setIndeterminate(true);

		int filesProcessed = 0;
		for (DomainFile file : ProjectDataUtils.descendantFiles(rootFolder32)) {
			if (monitor.isCancelled()) {
				break;
			}

			Map<String, String> metadata = file.getMetadata();
			String langId = metadata.get("Language ID");
			if (langId != null && langId.indexOf(":64:") != -1) {
				String origName = file.getPathname();
				DomainFolder destFolder =
					resolvePath(projRoot,
						rootFolder64Str +
							file.getParent().getPathname().substring(rootFolder32Str.length()),
						true);
				DomainFile newFile = file.moveTo(destFolder);
				println("Moved " + origName + " to " + newFile.getPathname());
				filesProcessed++;
			}
		}
		long end_ts = System.currentTimeMillis();

		println("Finished segregating for folder: " + rootFolder32.getPathname());
		println("Total files: " + filesProcessed);
		println("Total time: " + (end_ts - start_ts));
	}

	public static DomainFolder resolvePath(DomainFolder folder, String path,
			boolean createIfMissing) throws InvalidNameException, IOException {
		String[] pathParts = path.split("/");
		for (String part : pathParts) {
			if (part.isEmpty()) {
				continue;
			}
			DomainFolder subfolder = folder.getFolder(part);
			if (subfolder == null && createIfMissing) {
				subfolder = folder.createFolder(part);
			}
			if (subfolder == null) {
				return null;
			}
			folder = subfolder;
		}
		return folder;
	}

}
