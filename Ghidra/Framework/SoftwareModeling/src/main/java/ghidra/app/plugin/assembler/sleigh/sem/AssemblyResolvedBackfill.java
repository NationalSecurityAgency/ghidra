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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.Map;

import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;

public interface AssemblyResolvedBackfill extends AssemblyResolution {

	/**
	 * Get the expected length of the instruction portion of the future encoding
	 * 
	 * This is used to make sure that operands following a to-be-determined encoding are placed
	 * properly. Even though the actual encoding cannot yet be determined, its length can.
	 * 
	 * @return the total expected length (including the offset)
	 */
	int getInstructionLength();

	@Override
	AssemblyResolvedBackfill shift(int amt);

	/**
	 * Attempt (again) to solve the expression that generated this backfill record
	 * 
	 * <p>
	 * This will attempt to solve the same expression and goal again, using the same parameters as
	 * were given to the original attempt, except with additional defined symbols. Typically, the
	 * symbol that required backfill is {@code inst_next}. This method will not throw
	 * {@link NeedsBackfillException}, since that would imply the missing symbol(s) from the
	 * original attempt are still missing. Instead, the method returns an instance of
	 * {@link AssemblyResolvedError}.
	 * 
	 * @param solver a solver, usually the same as the one from the original attempt.
	 * @param vals the defined symbols, usually the same, but with the missing symbol(s).
	 * @return the solution result
	 */
	AssemblyResolution solve(RecursiveDescentSolver solver, Map<String, Long> vals,
			AssemblyResolvedPatterns cur);
}
