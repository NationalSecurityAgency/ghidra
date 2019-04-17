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
//Use this script to dump the information about the function bit patterns for the 
// current function to the ghidra console.
//@category FunctionStartPatterns
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.bitpatterns.info.DataGatheringParams;
import ghidra.bitpatterns.info.FunctionBitPatternInfo;
import ghidra.program.model.listing.Function;

public class DumpFunctionBitPatternInfoForCurrentFunctionScript extends GhidraScript {

	public static final int NUM_FIRST_BYTES = 10;
	public static final int NUM_FIRST_INSTRUCTIONS = 4;
	public static final int NUM_PRE_BYTES = 10;
	public static final int NUM_PRE_INSTRUCTIONS = 4;
	public static final int NUM_RETURN_BYTES = 12;
	public static final int NUM_RETURN_INSTRUCTIONS = 4;
	public static final List<String> contextRegisters = null;

	@Override
	protected void run() throws Exception {

		DataGatheringParams params = new DataGatheringParams();
		params.setNumPreBytes(NUM_PRE_BYTES);
		params.setNumFirstBytes(NUM_FIRST_BYTES);
		params.setNumReturnBytes(NUM_RETURN_BYTES);
		params.setNumPreInstructions(NUM_PRE_INSTRUCTIONS);
		params.setNumFirstInstructions(NUM_FIRST_INSTRUCTIONS);
		params.setNumReturnInstructions(NUM_RETURN_INSTRUCTIONS);
		params.setContextRegisters(contextRegisters);

		Function func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
		if (func == null) {
			popup("No function at currentAddress " + currentAddress.toString());
			return;
		}
		FunctionBitPatternInfo fStart = new FunctionBitPatternInfo(currentProgram, func, params);
		printf("%s\n\n", fStart.toString());

	}

}
