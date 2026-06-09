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
package ghidra.pcode.emu.jit.gen.var;

import ghidra.pcode.emu.jit.var.JitInputVar;

/**
 * The generator for a (whole) local variable that is input to the passage.
 */
public enum WholeInputVarGen implements InputVarGen {
	/** Singleton */
	GEN;

	@Override
	public ValGen<JitInputVar> subpiece(int byteOffset, int maxByteSize) {
		return new SubInputVarGen(byteOffset, maxByteSize);
	}
}
