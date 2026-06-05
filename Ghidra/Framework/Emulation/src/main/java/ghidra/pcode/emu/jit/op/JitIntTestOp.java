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
 * A binary p-code operator use-def node with {@link JitTypeBehavior#INTEGER int} inputs and a
 * boolean ({@link JitTypeBehavior#INTEGER int}) output.
 * 
 * @implNote Correct. This doesn't change anything, because boolean is int. Nevertheless, we keep
 *           this here because it forms a useful category of p-code ops. Also, if we ever need to
 *           formalize the "boolean" type, we'll already have this in place.
 */
public interface JitIntTestOp extends JitIntBinOp {
	@Override
	default JitTypeBehavior type() {
		return JitTypeBehavior.INTEGER;
	}
}
