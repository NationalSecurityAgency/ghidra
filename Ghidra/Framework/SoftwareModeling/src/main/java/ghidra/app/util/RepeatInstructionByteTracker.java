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
package ghidra.app.util;

import ghidra.program.model.address.AddressSetView;

/**
 * <code>RepeatInstructionByteTracker</code> provides pseudo-disassemblers the ability to track
 * repeated bytes during disassembly of a block of instructions.
 */
public class RepeatInstructionByteTracker {

	private AddressSetView repeatPatternLimitIgnoredRegion;
	private int repeatPatternLimit;

	private int repeatPatternCnt;
	private byte repeatByteValue;

	/**
	 * Constructor.
	 * @param repeatPatternLimit maximum number of instructions containing the same repeated 
	 * byte values.  A value less than or equal to 0 will disable counting.
	 * @param repeatPatternLimitIgnoredRegion optional set of addresses where check is not 
	 * performed or null for check to be performed everywhere.
	 */
	public RepeatInstructionByteTracker(int repeatPatternLimit,
			AddressSetView repeatPatternLimitIgnoredRegion) {
		this.repeatPatternLimit = repeatPatternLimit;
		this.repeatPatternLimitIgnoredRegion = repeatPatternLimitIgnoredRegion;
	}

	/**
	 * Reset internal counter.  This should be performed before disassembling
	 * a new block of instructions.
	 */
	public void reset() {
		repeatPatternCnt = 0;
	}

	/**
	 * Check the next instruction within a block of instructions.
	 * @param inst next instruction
	 * @return true if repeat limit has been exceeded, else false.  
	 * If the repeat limit has been set &lt;= 0 false will be returned.
	 */
	public boolean exceedsRepeatBytePattern(PseudoInstruction inst) {

		if (repeatPatternLimit <= 0) {
			return false;
		}
		if (repeatPatternLimitIgnoredRegion != null &&
			repeatPatternLimitIgnoredRegion.contains(inst.getAddress())) {
			repeatPatternCnt = 0;
			return false;
		}

		Byte repeatedByte = inst.getRepeatedByte();
		if (repeatedByte == null) {
			repeatPatternCnt = 0;
		}
		else if (repeatByteValue == repeatedByte) {
			if (++repeatPatternCnt > repeatPatternLimit) {
				repeatPatternCnt = 0;
				return true;
			}
		}
		else {
			repeatByteValue = repeatedByte;
			repeatPatternCnt = 1;
		}
		return false;
	}

	/**
	 * Set the maximum number of instructions in a single run which contain the same byte values.
	 * @param maxInstructions limit on the number of consecutive instructions with the same 
	 * byte values.  A non-positive value (&lt;= 0) will disable the 
	 * {@link #exceedsRepeatBytePattern(PseudoInstruction)} checking.
	 * 
	 */
	public void setRepeatPatternLimit(int maxInstructions) {
		this.repeatPatternLimit = maxInstructions;
	}

	/**
	 * Set the region over which the repeat pattern limit will be ignored.
	 * @param set region over which the repeat pattern limit will be ignored
	 */
	public void setRepeatPatternLimitIgnored(AddressSetView set) {
		this.repeatPatternLimitIgnoredRegion = set;
	}

}
