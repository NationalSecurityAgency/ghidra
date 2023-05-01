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
package ghidra.file.formats.dump.cmd;

import java.util.*;

import docking.widgets.ListSelectionTableDialog;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class ModuleToPeHelper {

	public static void queryModules(Program program, TaskMonitor taskMon) {

		Memory memory = program.getMemory();
		ProgramModule root = program.getListing().getDefaultRootModule();
		Group[] children = root.getChildren();
		List<String> names = new ArrayList<>();
		Map<String, Group> map = new HashMap<>();
		for (Group child : children) {
			names.add(child.getName());
			map.put(child.getName(), child);
		}
		ListSelectionTableDialog<String> dialog =
			new ListSelectionTableDialog<String>("Modules To Apply", names);
		List<String> selected = dialog.showSelectMultiple(null);

		for (String key : selected) {
			Group value = map.get(key);
			if (value instanceof ProgramFragment) {
				ProgramFragment mod = (ProgramFragment) value;
				if (mod.isEmpty()) {
					continue;
				}
				try {
					taskMon.setMessage("Analyzing " + mod.getName());
					taskMon.checkCancelled();
					ByteProvider provider = new ProgramInsertByteProvider(memory, mod);

					DumpPeShim loader = new DumpPeShim((ProgramDB) program);
					loader.load(provider, null, null, program, mod,
						taskMon, new MessageLog());
				}
				catch (Exception e) {
					// Ignore
					Msg.error(null, e.getMessage());
					taskMon.clearCancelled();
				}
			}
		}
	}


}
