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
package ghidra.pcode.emu.util;

/**
 * The most basic implementation of {@link CountsPcodeOps}
 */
public class PcodeOpCounter implements CountsPcodeOps {
	private int instructions;
	private int trailingOps;

	/**
	 * Count one additional op
	 * 
	 * @param startsInstruction true if this op is the beginning of a new instruction
	 */
	public void countOp(boolean startsInstruction) {
		if (startsInstruction) {
			instructions++;
			trailingOps = 1;
		}
		else {
			trailingOps++;
		}
	}

	/**
	 * Count some number of additional instructions and ops
	 * <p>
	 * If there are no new instructions, then the trailing ops are added to those already counted.
	 * If there is 1 or more new instructions, those are added to those already counted, but
	 * trailing ops is reset to only count those given.
	 * 
	 * @param instructions the number of instructions
	 * @param trailingOps the number of trailing ops
	 */
	public void count(int instructions, int trailingOps) {
		if (instructions != 0) {
			this.instructions += instructions;
			this.trailingOps = trailingOps;
		}
		else {
			this.trailingOps += trailingOps;
		}
	}

	/**
	 * Count some number of additional instructions and ops
	 * <p>
	 * This works as in {@link #count(int, int)} but the counts are taken from another counter
	 * 
	 * @param counter the other counter
	 */
	public void count(CountsPcodeOps counter) {
		count(counter.instructionCount(), counter.trailingOpCount());
	}

	@Override
	public int instructionCount() {
		return instructions;
	}

	@Override
	public int trailingOpCount() {
		return trailingOps;
	}
}
