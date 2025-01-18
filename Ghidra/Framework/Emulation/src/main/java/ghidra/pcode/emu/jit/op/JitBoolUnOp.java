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
package ghidra.pcode.emu.jit.op;

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;

/**
 * A unary p-code operator use-def node with boolean ({@link JitTypeBehavior#INTEGER int}) types.
 */
public interface JitBoolUnOp extends JitUnOp {
	@Override
	default JitTypeBehavior uType() {
		return JitTypeBehavior.INTEGER;
	}

	@Override
	default JitTypeBehavior type() {
		return JitTypeBehavior.INTEGER;
	}
}
