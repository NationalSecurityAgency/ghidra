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
package ghidra.app.util.viewer.field;

import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

import java.math.BigInteger;

public class HexagonParallelInstructionHelper implements ParallelInstructionLanguageHelper {

	public HexagonParallelInstructionHelper() {
	}

	@Override
	public String getMnemonicPrefix(Instruction instr) {
		if (isParallelInstruction(instr)) {
			return "||";
		}
		return null;
	}

	@Override
	public boolean isParallelInstruction(Instruction instruction) {

		Register packetOffsetReg = instruction.getRegister("packetOffset");
		if (packetOffsetReg == null) {
			return false;
		}
		BigInteger value = instruction.getValue(packetOffsetReg, false);
		return value.intValue() != 0;
	}

	@Override
	public boolean isEndOfParallelInstructionGroup(Instruction instruction) {
		try {
			byte[] bytes = instruction.getBytes();
			// assume little endian'
			// End of packet instruction will have PP='11' or EE='00'
			int bits = (bytes[1] & 0xC0) >> 6;
			return (bits == 0 || bits == 3);
		}
		catch (Exception e) {
			// ignore
		}
		return true;
	}

}
