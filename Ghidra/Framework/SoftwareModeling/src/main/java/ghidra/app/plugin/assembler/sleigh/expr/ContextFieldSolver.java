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
package ghidra.app.plugin.assembler.sleigh.expr;

import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.expression.ContextField;

/**
 * Solves expressions of a context register field
 * 
 * Essentially, this just encodes the goal into the field, if it can be represented in the given
 * space and format. Otherwise, there is no solution.
 */
public class ContextFieldSolver extends AbstractExpressionSolver<ContextField> {

	public ContextFieldSolver() {
		super(ContextField.class);
	}

	@Override
	public AssemblyResolution solve(ContextField cf, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) {
		assert cf.minValue() == 0; // In case someone decides to do signedness there.
		if (!goal.isInRange(cf.maxValue(), cf.hasSignbit())) {
			return AssemblyResolution.error("Value " + goal + " is not valid for " + cf,
				description, null);
		}
		AssemblyPatternBlock block = AssemblyPatternBlock.fromContextField(cf, goal);
		return AssemblyResolution.contextOnly(block, description, null);
	}

	@Override
	public MaskedLong getValue(ContextField cf, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur) {
		if (cur == null) {
			return null;
		}
		return valueForResolution(cf, cur);
	}

	@Override
	public int getInstructionLength(ContextField cf, Map<Integer, Object> res) {
		return 0; // this is a context field, not an instruction (token) field
	}

	@Override
	public MaskedLong valueForResolution(ContextField cf, AssemblyResolvedConstructor rc) {
		int size = cf.getByteEnd() - cf.getByteStart() + 1;
		MaskedLong res = rc.readContext(cf.getByteStart(), size);
		res = res.shiftRight(cf.getShift());
		if (cf.hasSignbit()) {
			res = res.signExtend(cf.getEndBit() - cf.getStartBit() + 1);
		}
		else {
			res = res.zeroExtend(cf.getEndBit() - cf.getStartBit() + 1);
		}
		return res;
	}
}
