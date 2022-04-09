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

/**
 * A tree of generated assembly node states, paired with the resulting patterns
 * 
 * <p>
 * This is used as the intermediate result when generating states, since the patterns must be
 * propagated to each operand as generation proceeds. Usually, the patterns in the final output are
 * discarded, and machine code generation proceeds using only the state tree.
 */
public class AssemblyGeneratedPrototype {
	protected final AbstractAssemblyState state;
	protected final AssemblyResolvedPatterns patterns;

	public AssemblyGeneratedPrototype(AbstractAssemblyState state,
			AssemblyResolvedPatterns patterns) {
		this.state = state;
		this.patterns = patterns;
	}

	@Override
	public String toString() {
		return state + " [" + patterns + "]";
	}
}
