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
import ghidra.app.plugin.processors.sleigh.expression.SegInstructionValue;

/**
 * "Solves" expressions of {@code seg_next}
 * 
 * <p>
 * Works like the constant solver, but takes the value of {@code seg_next}, which is given by the
 * segment value of the current instruction.
 * 
 * <p>
 * <b>NOTE:</b> This solver requires backfill, since the value of {@code seg_next} is not known
 * until possible prefixes have been considered.
 */
public class SegInstructionValueSolver extends AbstractExpressionSolver<SegInstructionValue> {

	public SegInstructionValueSolver() {
		super(SegInstructionValue.class);
	}

	@Override
	public AssemblyResolution solve(AbstractAssemblyResolutionFactory<?, ?> factory,
			SegInstructionValue exp, MaskedLong goal, Map<String, Long> vals,
			AssemblyResolvedPatterns cur, Set<SolverHint> hints, String description)
			throws NeedsBackfillException {
		throw new AssertionError(
			"INTERNAL: Should never be asked to solve for " + AssemblyTreeResolver.SEG_NEXT);
	}

	@Override
	public MaskedLong getValue(SegInstructionValue iv, Map<String, Long> vals,
			AssemblyResolvedPatterns cur) throws NeedsBackfillException {
		Long segNext = vals.get(AssemblyTreeResolver.SEG_NEXT);
		if (segNext == null) {
			throw new NeedsBackfillException(AssemblyTreeResolver.SEG_NEXT);
		}
		return MaskedLong.fromLong(segNext);
	}

	@Override
	public int getInstructionLength(SegInstructionValue iv) {
		return 0;
	}

	@Override
	public MaskedLong valueForResolution(SegInstructionValue exp, Map<String, Long> vals,
			AssemblyResolvedPatterns rc) {
		Long segNext = vals.get(AssemblyTreeResolver.SEG_NEXT);
		if (segNext == null) {
			/**
			 * This method is used in forward state construction, so just leave unknown. This may
			 * cause unresolvable trees to get generated, but we can't know that until we try to
			 * resolve them.
			 */
			return MaskedLong.UNKS;
		}
		return MaskedLong.fromLong(segNext);
	}
} 