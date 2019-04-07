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
// Script repairs incorrect use of Function Definition applied directly 
// on function parameters/variables when it should be a pointer to a
// Function Definition.  This resolves variable size errors which
// result from this bad data state.
//
//@category Repair
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.Comparator;

public class RepairFuncDefinitionUsageScript extends GhidraScript {

	private static class MyVariableOffsetComparator implements Comparator<Variable> {

		@Override
		public int compare(Variable o1, Variable o2) {
			// sort with most positive offset first
			long offset1 = getOffset(o1);
			long offset2 = getOffset(o2);
			if (offset1 == offset2) {
				return 0;
			}
			if (offset1 > offset2) {
				return -1;
			}
			return 1;
		}

		private long getOffset(Variable var) {
			Address minAddress = var.getMinAddress();
			if (minAddress == null) {
				return 0;
			}
			return minAddress.getOffset();
		}
	}

	private static Comparator<Variable> VARIABLE_COMPARATOR = new MyVariableOffsetComparator();

	@Override
	public void run() throws Exception {

		if (currentProgram == null) {
			return;
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		int cnt = 0;
		int bad = 0;
		int total = 0;

		FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function func = functions.next();

			Variable[] vars = func.getAllVariables();
			Arrays.sort(vars, VARIABLE_COMPARATOR);

			for (Variable var : vars) {
				++total;
				if (var.getVariableStorage().isBadStorage()) {
					Msg.error(this,
						"Repair failed at " + var.getName() + "@" + func.getEntryPoint() +
							": variable has invalid storage!");
					++bad;
					continue;
				}
				DataType dt = var.getDataType();
				if (dt instanceof FunctionDefinition) {
					dt = PointerDataType.getPointer(dt, dtm);
					try {
						try {
							var.setDataType(dt, SourceType.ANALYSIS);
						}
						catch (VariableSizeException e) {
							Msg.warn(this,
								"Repair conflict at " + var.getName() + "@" + func.getEntryPoint() +
									" affected stack offset of other variables/parameters");

							var.setDataType(dt, true, true, SourceType.ANALYSIS);
						}
						++cnt;
					}
					catch (InvalidInputException e) {
						Msg.warn(this,
							"Repair failed at " + var.getName() + "@" + func.getEntryPoint() + ":" +
								e.toString());
					}
				}
			}
		}

		popup("Repaired " + cnt + " variables/parameters out of " + total + " variables, " + bad +
			" bad variables found");

	}

}
