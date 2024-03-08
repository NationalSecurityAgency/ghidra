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
package ghidra.app.plugin.core.analysis;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AnalysisTask extends BackgroundCommand<Program> {
	AnalysisScheduler scheduler;
	private MessageLog log;

	public AnalysisTask(AnalysisScheduler scheduler, MessageLog log) {
		super(scheduler.getName(), true, true, false);
		this.scheduler = scheduler;
		this.log = log;
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) {
		try {
			return scheduler.runAnalyzer(program, monitor, log);
		}
		catch (CancelledException e) {
			return false;
		}
	}

	@Override
	public void dispose() {
		super.dispose();
		scheduler.runCanceled();
	}

}
