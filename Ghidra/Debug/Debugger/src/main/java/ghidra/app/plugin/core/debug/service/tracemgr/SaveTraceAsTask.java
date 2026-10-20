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
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.Trace;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SaveTraceAsTask extends AbstractSaveTraceTask {
	public SaveTraceAsTask(PluginTool tool, Trace trace, AskTraceResult asked,
			boolean force) {
		super("Save %s as %s".formatted(trace, asked.name()), tool, trace, asked, force);
	}

	@Override
	protected void saveTrace(TaskMonitor monitor)
			throws CancelledException, InvalidNameException, IOException {
		DomainFile exists = asked.parent().getFile(asked.name());
		if (exists != null) {
			exists.delete();
		}
		asked.parent().createFile(asked.name(), trace, monitor);
		trace.setName(asked.name());
		trace.save("Save As", monitor);
		/**
		 * NOTE: Refrain from modifying "Trace Information", since that better indicates the
		 * *original* trace name, as reported by the back end debugger.
		 */
	}
}
