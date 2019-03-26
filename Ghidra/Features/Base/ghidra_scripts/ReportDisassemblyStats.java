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
//
// Reports some basic information about how the binary was disassembled.  If running in
// headless mode it also generates the signature file.
//
//@category Examples

import java.io.*;
import java.util.Iterator;

import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

public class ReportDisassemblyStats extends HeadlessScript {

	int totalNumOfFunctions = 0;
	double UNDEFINED_THRESHOLD = 50.0;
	double NOT_IN_FUNC_THRESHOLD = 50.0;

	@Override
	public void run() throws Exception {

		// find all the sections of memory marked as executable

		if (this.isRunningHeadless()) {
			runScript("MakeFuncsAtLabelsScript.java");
		}

		AddressSetView execMemSet = currentProgram.getMemory().getExecuteSet();
		InstructionIterator instIter =
			currentProgram.getListing().getInstructions(execMemSet, true);
		FunctionManager fm = currentProgram.getFunctionManager();
		//calculate the number of instructions not in functions and the total number of instructions
		int instCount = 0;
		int instNotInFuncCount = 0;
		int instByteCount = 0;
		while (instIter.hasNext()) {
			Instruction inst = instIter.next();
			instByteCount += inst.getBytes().length;
			Function func = fm.getFunctionContaining(inst.getAddress());
			if (func == null) {
				instNotInFuncCount++;
			}
			instCount++;
		}
		//count the number of defined data bytes
		int dataByteCount = 0;
		DataIterator dataIter = currentProgram.getListing().getData(execMemSet, true);
		while (dataIter.hasNext()) {
			Data data = dataIter.next();
			if (data.isDefined()) {
				dataByteCount += data.getBytes().length;
			}
		}

		long numTotalBytes = execMemSet.getNumAddresses();
		double undefinedPercentage =
			100.0 - (100.0 * (instByteCount + dataByteCount) / numTotalBytes);
		double notInFuncPercentage = instNotInFuncCount * 100.0 / instCount;

		printf("Name: %s", getProgramFile().toString());
		printf("Language: %s", currentProgram.getLanguageID());
		printf("CompilerSpec: %s", currentProgram.getCompilerSpec().getCompilerSpecID());
		printf("Number of functions: %d", fm.getFunctionCount());
		printf("Number of addresses: %d", numTotalBytes);
		printf("Percentage of undefined addresses: %f", undefinedPercentage);
		printf("Percentage of instructions not in functions: %f", notInFuncPercentage);

		Iterator<Bookmark> bmi = currentProgram.getBookmarkManager().getBookmarksIterator("Error");
		int numConflicts = 0;
		int numRelocationErrors = 0;
		while (bmi.hasNext()) {
			Bookmark bm = bmi.next();
			if (bm.toString().contains("conflicting")) {
				numConflicts++;
				continue;
			}
			if (bm.toString().contains("relocation")) {
				numRelocationErrors++;
				continue;
			}
			printf("!!%s", bm.toString());
		}
		printf("Number of conflicts: %d", numConflicts);
		printf("Number of relocation errors: %d", numRelocationErrors);
		if (this.isRunningHeadless()) {
			if ((undefinedPercentage <= UNDEFINED_THRESHOLD) &&
				(notInFuncPercentage <= NOT_IN_FUNC_THRESHOLD)) {
				totalNumOfFunctions += fm.getFunctionCount();
				printf("Total number of functions: %d", totalNumOfFunctions);
				//search for .siginfo file
				File siginfoFile = new File(getProgramFile().getAbsolutePath() + ".siginfo");
				boolean siginfoExists = siginfoFile.exists();
				if (!siginfoExists) {
					printf("No siginfo file found");
				}
				else {
					//read the .siginfo file and save the information to the project
					BufferedReader br = new BufferedReader(new FileReader(siginfoFile));
					String verinfo = br.readLine();
					br.close();
					Options propList = currentProgram.getOptions("Signature Info");
					propList.setString("Version Name", verinfo);
					printf("Saving version %s to project", verinfo);
				}
			}
			else {
				printf("Program not imported");
				setHeadlessContinuationOption(HeadlessContinuationOption.ABORT_AND_DELETE);
			}
			printf("");

		}

	}
}
