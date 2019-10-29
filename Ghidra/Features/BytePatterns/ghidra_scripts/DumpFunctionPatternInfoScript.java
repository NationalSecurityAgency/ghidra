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
//This script dumps information about byte and instructions in neighborhoods around function starts
//and returns to an XML file
//@category FunctionStartPatterns
import java.io.*;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.bitpatterns.info.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.Msg;

/**
 * Example of command to run this script headlessly:
 * ./analyzeHeadless /local/ghidraProjects/nonShared/ arm -recursive -process -noanalysis -postScript DumpFunctionPatternInfo.java
 */
public class DumpFunctionPatternInfoScript extends GhidraScript {
	private static int totalFuncs = 0;
	private static int programsAnalyzed = 0;

	@Override
	protected void run() throws Exception {
		if (!isRunningHeadless()) {
			totalFuncs = 0;
			programsAnalyzed = 0;
		}

		int numFirstBytes = askInt("Number of first bytes", "bytes");
		int numFirstInstructions = askInt("Number of first instructions", "instructions");
		int numPreBytes = askInt("Number of pre bytes", "bytes");
		int numPreInstructions = askInt("Number of pre instructions", "instructions");
		int numReturnBytes = askInt("Number of return bytes", "bytes");
		int numReturnInstructions = askInt("Number of return instructions", "instructions");
		String saveDirName = askString("Directory to save results", "directory");
		String contextRegsCSV = askString("Context register csv", "csv");

		File saveDir = new File(saveDirName);
		if (!saveDir.isDirectory()) {
			Msg.info(this, "Invalid save directory: " + saveDirName);
			return;
		}

		List<String> contextRegisters = DataGatheringParams.getContextRegisterList(contextRegsCSV);

		programsAnalyzed++;
		if (currentProgram == null) {
			Msg.info(this, "null current program: try again with the -process option");
			return;
		}

		if (currentProgram.getFunctionManager().getFunctionCount() == 0) {
			Msg.info(this, "No functions found in " + currentProgram.getName() + ", skipping.");
			return;
		}

		FunctionIterator fIter = currentProgram.getFunctionManager().getFunctions(true);
		DataGatheringParams params = new DataGatheringParams();
		params.setNumPreBytes(numPreBytes);
		params.setNumFirstBytes(numFirstBytes);
		params.setNumReturnBytes(numReturnBytes);
		params.setNumPreInstructions(numPreInstructions);
		params.setNumFirstInstructions(numFirstInstructions);
		params.setNumReturnInstructions(numReturnInstructions);
		params.setContextRegisters(contextRegisters);

		FileBitPatternInfo funcPatternList = new FileBitPatternInfo();
		funcPatternList.setLanguageID(currentProgram.getLanguageID().getIdAsString());
		funcPatternList.setGhidraURL("TODO: url");
		funcPatternList.setNumPreBytes(numPreBytes);
		funcPatternList.setNumPreInstructions(numPreInstructions);
		funcPatternList.setNumFirstBytes(numFirstBytes);
		funcPatternList.setNumFirstInstructions(numFirstInstructions);
		funcPatternList.setNumReturnBytes(numReturnBytes);
		funcPatternList.setNumReturnInstructions(numReturnInstructions);

		AddressSetView initialized = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
		while (fIter.hasNext()) {
			monitor.checkCanceled();
			Function func = fIter.next();
			if (func.isThunk()) {
				continue;
			}
			if (func.isExternal()) {
				continue;
			}
			if (!initialized.contains(func.getEntryPoint())) {
				continue;
			}
			if (currentProgram.getListing().getInstructionAt(func.getEntryPoint()) == null) {
				continue;
			}

			FunctionBitPatternInfo fStart =
				new FunctionBitPatternInfo(currentProgram, func, params);
			if (fStart.getFirstBytes() != null) {
				funcPatternList.getFuncBitPatternInfo().add(fStart);
				totalFuncs++;
			}
		}

		File savedFile = new File(saveDir.getAbsolutePath() + File.separator +
			currentProgram.getDomainFile().getPathname().replaceAll("/", "_") + "_" +
			currentProgram.getExecutableMD5() + "_funcInfo.xml");
		funcPatternList.toXmlFile(savedFile);
		Msg.info(this,
			"Programs analyzed: " + programsAnalyzed + "; total functions: " + totalFuncs);
	}
}
