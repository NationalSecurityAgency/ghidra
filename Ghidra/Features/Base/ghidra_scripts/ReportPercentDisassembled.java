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
// Reports the percentage of bytes in any executable section that were disassembled into instructions,
// or turned into defined data.
// This can be an "indicator" of how well the initial analysis was at finding all code.
//
// Assumes a program is open.
//
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

public class ReportPercentDisassembled extends GhidraScript {

	@Override
	public void run() throws Exception {

		// find all the sections of memory marked as executable
		Program prog = currentProgram;
		AddressSetView execMemSet = prog.getMemory().getExecuteSet();
		/*int myExecSetLen = 0;
		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		for (int i = 0; i < blocks.length; i++) {
			if (blocks[i].isExecute()) {
				myExecSetLen += blocks[i].getSize();
			}
		}*/

		// tally up all the bytes that have been marked as instructions
		//   (probably faster ways to do this, but it works)
		long numPossibleDis = execMemSet.getNumAddresses();
		InstructionIterator instIter = prog.getListing().getInstructions(execMemSet, true);
		int instCount = 0;
		while (instIter.hasNext()) {
			Instruction inst = instIter.next();
			instCount += inst.getLength();
		}
		DataIterator dataIter = prog.getListing().getData(execMemSet, true);
		int dataCount = 0;
		while (dataIter.hasNext()) {
			Data data = dataIter.next();
			if (data.isDefined()) {
				dataCount += data.getLength();
			}
		}

		// dump the info
		int total = instCount + dataCount;
		if (numPossibleDis != 0) {
			float coverage = (float) total / (float) numPossibleDis;
//	    	Msg.info(this,"execSetLen = " + numPossibleDis);
//	    	Msg.info(this,"MyExecSetLen = " + myExecSetLen);
//	    	Msg.info(this,"NumInsts = " + instCount);
//	    	Msg.info(this,"numData = " + dataCount);
//
//	    	Msg.info(this,"totalDis = " + total);
			float percentage = coverage * 100;
			Msg.info(this, "REPORT DISASSEMBLY EXTENT: " + prog.getName() + ": " + percentage +
				"% disassembled.");
		}
		return;

	}

}
