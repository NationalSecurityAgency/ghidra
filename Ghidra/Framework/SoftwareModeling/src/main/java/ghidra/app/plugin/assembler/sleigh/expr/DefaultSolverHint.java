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

/**
 * A set of built-in {@link SolverHint}s
 */
public enum DefaultSolverHint implements SolverHint {
	/**
	 * A multiplication solver is synthesizing goals with repetition
	 */
	GUESSING_REPETITION,
	/**
	 * A boolean or solver which matches a circular shift is solving the value having guessed a
	 * shift
	 */
	GUESSING_CIRCULAR_SHIFT_AMOUNT,
	/**
	 * A left-shift solver is solving the value having guessed a shift
	 */
	GUESSING_LEFT_SHIFT_AMOUNT,
	/**
	 * A right-shift solver is solving the value having guessed a shift
	 */
	GUESSING_RIGHT_SHIFT_AMOUNT;
}
