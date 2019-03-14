/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.function;

import ghidra.app.cmd.function.FunctionPurgeAnalysisCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class X86FunctionPurgeAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "X86 Function Callee Purge";
	private static final String DESCRIPTION =
		"Figures out the function Purge value for Callee cleaned up function call parameters (stdcall) on X86 platforms.";

	public X86FunctionPurgeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS);
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {
		BackgroundCommand cmd;

		cmd = new FunctionPurgeAnalysisCmd(set);

		cmd.applyTo(program, monitor);
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Only analyze 32-bit or less X86 programs
		Processor processor = program.getLanguage().getProcessor();
		if (program.getLanguage().getDefaultSpace().getSize() > 32) {
			return false;
		}
		return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
	}

}
