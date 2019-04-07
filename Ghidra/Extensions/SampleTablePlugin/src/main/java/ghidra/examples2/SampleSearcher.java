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
package ghidra.examples2;

import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.task.TaskMonitor;

public class SampleSearcher {

	private Program program;

	public SampleSearcher(Program program) {
		this.program = program;

	}

	public void search(Accumulator<SearchResults> accumulator, TaskMonitor monitor) {

		FunctionIterator it = program.getFunctionManager().getFunctions(true);
		monitor.initialize(program.getFunctionManager().getFunctionCount());
		while (it.hasNext()) {
			if (monitor.isCancelled()) {
				monitor.clearCanceled();  //otherwise the partial results won't be shown
				break;
			}
			Function fun = it.next();
			monitor.incrementProgress(1);
			if (fun.getParameterCount() == 0) {
				accumulator.add(new SearchResults(fun.getEntryPoint(), fun.getName()));
			}
		}
	}

	public Program getProgram() {
		return program;
	}

}
