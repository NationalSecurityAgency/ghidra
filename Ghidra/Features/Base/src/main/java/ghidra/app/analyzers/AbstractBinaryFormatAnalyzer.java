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
package ghidra.app.analyzers;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractBinaryFormatAnalyzer extends AbstractAnalyzer {
	protected BinaryAnalysisCommand command;

	protected AbstractBinaryFormatAnalyzer(BinaryAnalysisCommand command) {
		super(command.getName(), command.getName(), AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
		this.command = command;
	}

	final public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		try {
			return command.applyTo(program, monitor);
		}
		catch (Exception e) {
			log.appendException(e);
			log.setStatus(e.toString());
		}
		finally {
			log.copyFrom(command.getMessages());
		}
		return false;
	}

	final public boolean canAnalyze(Program program) {
		return command.canApply(program);
	}

	final public boolean getDefaultEnablement(Program program) {
		return command.canApply(program);
	}

}
