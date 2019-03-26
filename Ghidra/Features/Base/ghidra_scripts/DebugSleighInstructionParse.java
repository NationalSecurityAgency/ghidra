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
// Attempt to parse single instruction from memory bytes at current location.
// Parse trace output written to Tool Console.
// @category sleigh
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.util.StringUtilities;


public class DebugSleighInstructionParse extends GhidraScript {

	@Override
	public void run() throws Exception {
		
		if (currentProgram == null || currentAddress == null) {
			return;
		}

		try {
			SleighDebugLogger logger = new SleighDebugLogger(currentProgram, currentAddress, SleighDebugMode.VERBOSE);

			if (!logger.parseFailed()) {
				logger.append("\n");
				
				byte[] mask = logger.getInstructionMask();
				byte[] value = logger.getMaskedBytes(mask);
				
				logger.append("Instr Mask:  ");
				logger.append(mask, -1, -1);
				logger.append("\nInstr Value: ");
				logger.append(value, -1, -1);
				
				for (int i = 0; i < logger.getNumOperands(); i++) {
					mask = logger.getOperandValueMask(i);
					logger.append("\nOp-" + i + " Mask:   " + getFormattedBytes(mask));
					logger.append("\nOp-" + i + " Value:  " + getFormattedBytes(logger.getMaskedBytes(mask)));
				}
			}
			println(logger.toString());
			
		} catch (Exception e) {
			println(e.getMessage());
		}

	}
	
	 private String getFormattedBytes(byte[] value) {
			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < value.length; i++) {
			String byteStr = StringUtilities.pad(Integer.toBinaryString(value[i] & 0xff), '0', 8);
				buf.append(byteStr);
				if (i < (value.length-1)) {
					buf.append(".");
				}
			}
			return buf.toString();
		}
	
}
