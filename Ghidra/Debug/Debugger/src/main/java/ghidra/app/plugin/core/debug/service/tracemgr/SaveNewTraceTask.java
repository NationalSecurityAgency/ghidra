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
package ghidra.app.plugin.core.debug.service.tracemgr;

import java.io.IOException;

import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin.AskTraceResult;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

public class SaveNewTraceTask extends AbstractSaveTraceTask {
	public SaveNewTraceTask(PluginTool tool, Trace trace, AskTraceResult asked, boolean force) {
		super("Save trace " + trace.getName(), tool, trace, asked, force);
	}

	@Override
	protected void saveTrace(TaskMonitor monitor)
			throws CancelledException, InvalidNameException, IOException {
		String filename = asked.name();
		for (int i = 1;; i++) {
			try {
				asked.parent().createFile(filename, trace, monitor);
				break; // success, so fall through
			}
			catch (DuplicateFileException e) {
				filename = "%s.%d".formatted(asked.name(), i);
			}
		}
		trace.save("Initial save", monitor);
	}
}
