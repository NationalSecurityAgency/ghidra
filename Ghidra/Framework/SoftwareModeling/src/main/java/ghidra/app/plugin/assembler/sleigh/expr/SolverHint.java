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

import java.util.*;

/**
 * A type for solver hints
 * 
 * Hints inform "sub-"solvers of the techniques already being applied by the calling solvers. This
 * helps prevent situations where, e.g., two multiplication solvers (applied to repeated or nested
 * multiplication) both attempt to synthesize new goals for repetition. This sort of expression is
 * common when decoding immediates in the AArch64 specification.
 * 
 * Using an interface implemented by an enumeration (instead of just using the enumeration directly)
 * eases expansion by extension without modifying the core code.
 * 
 * @see DefaultSolverHint
 */
public interface SolverHint {
	static Set<SolverHint> with(Set<SolverHint> set, SolverHint... plus) {
		Set<SolverHint> hints = new HashSet<>(set);
		hints.addAll(Set.of(plus));
		return Collections.unmodifiableSet(hints);
	}
}
