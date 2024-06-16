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
package sarif.export.func;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;

public class ExtFunctionStack implements IsfObject {

	int localVarSize;
	int parameterOffset;
	int returnAddressOffset;
	int purgeSize;

	List<ExtFunctionStackVar> stackVars = new ArrayList<>();

	public ExtFunctionStack(StackFrame stackFrame, boolean hasCustomStorage) {
		localVarSize = stackFrame.getLocalSize();
		parameterOffset = stackFrame.getParameterOffset();
		returnAddressOffset = stackFrame.getReturnAddressOffset();

		Variable[] vars = stackFrame.getStackVariables();
		if (hasCustomStorage) {
			Arrays.sort(vars, new Comparator<Variable>() {
				@Override
				public int compare(Variable o1, Variable o2) {
					if (o1 instanceof Parameter p1 && o2 instanceof Parameter p2) {
						return p1.getOrdinal() - p2.getOrdinal();
					}
					return o1.getStackOffset() - o2.getStackOffset();
				}
			});
		}
		for (Variable var : vars) {
			stackVars.add(new ExtFunctionStackVar(var));
		}
	}

	public void setPurgeSize(int purgeSize) {
		this.purgeSize = purgeSize;
	}

}
