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
package ghidra.pcode.emu.jit.gen.util;

/**
 * Utility for explicitly checking the stack at a given point in a bytecode sequence.
 */
public interface Check {
	/**
	 * Explicitly check the stack at this point in the bytecode sequence
	 * <p>
	 * This is meant to be used with chosen type parameters, e.g.:
	 * 
	 * <pre>
	 * return em
	 * 		.emit(Op::ldc__i, 42)
	 * 		.emit(Check::&lt;Ent&lt;Bot, TInt&gt;&gt; expect);
	 * </pre>
	 * <p>
	 * Granted, that's not a particularly complicated case warranting such a check, it demonstrates
	 * the idiom for placing the check. These are often only in place while the sequence is devised,
	 * and then removed.
	 * 
	 * @param <N> the expected stack
	 * @param em the emitter typed with the expected stack
	 * @return the same emitter
	 */
	static <N> Emitter<N> expect(Emitter<N> em) {
		return em;
	}
}
