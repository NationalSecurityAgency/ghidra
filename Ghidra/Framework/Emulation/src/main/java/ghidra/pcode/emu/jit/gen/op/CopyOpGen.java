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
package ghidra.pcode.emu.jit.gen.op;

import ghidra.pcode.emu.jit.op.JitCopyOp;

/**
 * The generator for a {@link JitCopyOp copy}.
 * <p>
 * This is identical to {@link IntZExtOpGen}, except that we expect (require?) the output and input
 * operand to agree in size, and so we don't actually expect any extension. In the event that is not
 * the case, it seems agreeable that zero extension is applied.
 */
public enum CopyOpGen implements IntExtUnOpGen<JitCopyOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}
}
