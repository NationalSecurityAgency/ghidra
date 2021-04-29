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

import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Background task to artificially kick off Auto analysis by
 * calling anything that analyzes bytes.
 */
public class OneShotAnalysisCommand extends BackgroundCommand {
	private Analyzer analyzer;
	private AddressSetView set;
	private MessageLog log;

	public OneShotAnalysisCommand(Analyzer analyzer, AddressSetView set, MessageLog log) {
		super(analyzer.getName() + " - One Time", true, true, false);
		this.analyzer = analyzer;
		this.set = set;
		this.log = log;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		try {
			monitor.setMessage(analyzer.getName());
			return analyzer.added(program, set, monitor, log);
		}
		catch (CancelledException e) {
			return false;
		}
	}

	@Override
	public String getStatusMsg() {
		String statusMessage = log.getStatus();

		if (statusMessage.length() > 0) {
			return statusMessage;
		}

		return null;
	}
}
