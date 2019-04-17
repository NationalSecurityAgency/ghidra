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
//Displays the count of programs that have a specific number of revisions. 
//@category    Version Control
//@menupath    Tools.Version Control.Version Summary

import java.util.Arrays;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.util.datastruct.IntIntHashtable;

public class VersionControl_VersionSummary extends GhidraScript {

	public VersionControl_VersionSummary() {
	}


	@Override
	public void run() throws Exception {

		if (currentProgram != null) {
			popup("This script should be run from a tool with no open programs");
			return;
		}

		DomainFolder rootFolder =
			askProjectFolder("Choose root folder to recursively get version summaries");

		long start_ts = System.currentTimeMillis();
		monitor.initialize(0);
		monitor.setIndeterminate(true);

		int filesProcessed = 0;
		IntIntHashtable versionCounts = new IntIntHashtable();
		for (DomainFile file : ProjectDataUtils.descendantFiles(rootFolder)) {
			if (monitor.isCancelled()) {
				break;
			}

			filesProcessed++;

			int ver = 0;
			if (file.isVersioned()) {
				ver = file.getLatestVersion();
			}
			int verCount = versionCounts.contains(ver) ? versionCounts.get(ver) : 0;
			versionCounts.put(ver, verCount + 1);
		}
		long end_ts = System.currentTimeMillis();

		println("Finished gathering summary info for folder: " + rootFolder);
		println("Total files: " + filesProcessed);
		println("Total time: " + (end_ts - start_ts));

		int[] keys = versionCounts.getKeys();
		Arrays.sort(keys);
		for (int ver : keys) {
			int count = versionCounts.get(ver);
			println("Files with [" + ver + "] versions: " + count);
		}
	}

}
