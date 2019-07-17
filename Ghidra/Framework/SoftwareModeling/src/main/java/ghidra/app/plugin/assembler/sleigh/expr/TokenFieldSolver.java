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
import ghidra.app.plugin.processors.sleigh.expression.TokenField;

/**
 * Solves expressions of a token (instruction encoding) field
 * 
 * Essentially, this just encodes the goal into the field, if it can be represented in the given
 * space and format. Otherwise, there is no solution.
 */
public class TokenFieldSolver extends AbstractExpressionSolver<TokenField> {

	public TokenFieldSolver() {
		super(TokenField.class);
	}

	@Override
	public AssemblyResolution solve(TokenField tf, MaskedLong goal, Map<String, Long> vals,
			Map<Integer, Object> res, AssemblyResolvedConstructor cur, Set<SolverHint> hints,
			String description) {
		assert tf.minValue() == 0; // In case someone decides to do signedness there.
		if (!goal.isInRange(tf.maxValue(), tf.hasSignbit())) {
			return AssemblyResolution.error("Value " + goal + " is not valid for " + tf,
				description, null);
		}
		AssemblyPatternBlock block = AssemblyPatternBlock.fromTokenField(tf, goal);
		return AssemblyResolution.instrOnly(block, description, null);
	}

	@Override
	public MaskedLong getValue(TokenField tf, Map<String, Long> vals, Map<Integer, Object> res,
			AssemblyResolvedConstructor cur) {
		if (cur == null) {
			return null;
		}
		return valueForResolution(tf, cur);
	}

	@Override
	public int getInstructionLength(TokenField tf, Map<Integer, Object> res) {
		return tf.getByteEnd() + 1;
	}

	@Override
	public MaskedLong valueForResolution(TokenField tf, AssemblyResolvedConstructor rc) {
		int size = tf.getByteEnd() - tf.getByteStart() + 1;
		MaskedLong res = rc.readInstruction(tf.getByteStart(), size);
		if (!tf.isBigEndian()) {
			res = res.byteSwap(size);
		}
		res = res.shiftRight(tf.getShift());
		if (tf.hasSignbit()) {
			res = res.signExtend(tf.getBitEnd() - tf.getBitStart() + 1);
		}
		else {
			res = res.zeroExtend(tf.getBitEnd() - tf.getBitStart() + 1);
		}
		return res;
	}
}
