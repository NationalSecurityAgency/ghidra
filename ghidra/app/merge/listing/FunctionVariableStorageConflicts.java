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
package ghidra.app.merge.listing;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.VariableStorageConflicts;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;

class FunctionVariableStorageConflicts extends VariableStorageConflicts {

	private Function function1;
	private Function function2;

	/**
	 * Construct a VariableStorageConflicts object for the variables contained within two
	 * functions.
	 * @param function1
	 * @param function2
	 * @param ignoreParamToParamConflicts if true param-to-param overlaps will be ignored unless
	 * a param-to-local overlap occurs in which case all params will be pulled in to the
	 * overlap.  If true, it is assumed that the current overlap iteration was initiated by
	 * a parameter overlap check.
	 * @param monitor
	 * @throws CancelledException
	 */
	FunctionVariableStorageConflicts(Function function1, Function function2,
			boolean ignoreParamToParamConflicts, TaskMonitor monitor) throws CancelledException {
		super(Arrays.asList(function1.getAllVariables()),
			Arrays.asList(function2.getAllVariables()), ignoreParamToParamConflicts, monitor);
		this.function1 = function1;
		this.function2 = function2;
	}

	@Override
	public boolean isConflicted(Variable var1, Variable var2) {
		if (var1 != null) {
			if (var1.getFunction() != function1) {
				throw new IllegalArgumentException("var1 does not correspond to function1");
			}
		}
		if (var2 != null) {
			if (var2.getFunction() != function2) {
				throw new IllegalArgumentException("var2 does not correspond to function2");
			}
		}
		return super.isConflicted(var1, var2);
	}
}
