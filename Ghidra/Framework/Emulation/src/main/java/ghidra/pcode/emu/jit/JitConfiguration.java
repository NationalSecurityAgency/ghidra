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
package ghidra.pcode.emu.jit;

/**
 * The configuration for a JIT-accelerated emulator.
 * 
 * @param maxPassageInstructions The (soft) maximum number of instructions to decode per translated
 *            passage. A passage can consist of several control-flow connected basic blocks. The
 *            decoder will decode contiguous streams of instructions with fall-through (called
 *            <em>strides</em>), adding seeds where it encounters branches. It will not stop
 *            mid-stride, but checks the instruction count before proceeding to another seed. If it
 *            exceeds the max, it stops.
 * @param maxPassageOps The (soft) maximum number of p-code ops. This is similar to
 *            {@link #maxPassageInstructions}, but limits the number of p-code ops generated.
 *            <b>NOTE:</b> The JVM limits each method to 65,535 total bytes of bytecode. If this
 *            limit is exceeded, the ASM library throws an exception. When this happens, the
 *            compiler will retry the whole process, but with this configuration parameter halved.
 * @param maxPassageStrides The maximum number of strides to include.
 * @param removeUnusedOperations Some p-code ops produce outputs that are never used later. One
 *            common case is flags computed from arithmetic operations. If this option is enabled,
 *            the JIT compiler will remove those p-code ops.
 * @param emitCounters Causes the translator to emit a call to
 *            {@link JitPcodeThread#count(int, int)} at the start of each basic block.
 */
public record JitConfiguration(
		int maxPassageInstructions,
		int maxPassageOps,
		int maxPassageStrides,
		boolean removeUnusedOperations,
		boolean emitCounters) {

	/**
	 * Construct a default configuration
	 */
	public JitConfiguration() {
		this(1000, 5000, 10, true, true);
	}
}
