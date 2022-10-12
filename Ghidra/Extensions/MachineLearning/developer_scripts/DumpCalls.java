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
//Writes a list of the addresses of all call sites to a file.
//@category machineLearning

import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;

public class DumpCalls extends GhidraScript {

	private static final String DATA_DIR = "/local/calls";

	@Override
	protected void run() throws Exception {
		File outFile = new File(DATA_DIR + File.separator + currentProgram.getName() + "_calls");
		FileWriter fWriter = new FileWriter(outFile);
		BufferedWriter bWriter = new BufferedWriter(fWriter);
		InstructionIterator fIter = currentProgram.getListing().getInstructions(true);
		int numCalls = 0;
		int numInstructions = 0;
		while (fIter.hasNext()) {
			Instruction inst = fIter.next();
			if (inst.getPcode() == null || inst.getPcode().length == 0) {
				continue;
			}
			numInstructions++;
			for (int i = 0; i < inst.getPcode().length; i++) {
				PcodeOp pCode = inst.getPcode()[i];
				int opCode = pCode.getOpcode();
				if (opCode == PcodeOp.CALL || opCode == PcodeOp.CALLIND) {
					//printf("Inst: %s at %s\n", inst.toString(), inst.getAddress());
					numCalls++;
					bWriter.write(inst.getAddress().toString() + "\n");
				}
			}
		}
		printf("total num calls: %d\n", numCalls);
		printf("total num instructions: %d\n", numInstructions);
		bWriter.close();
	}

}
