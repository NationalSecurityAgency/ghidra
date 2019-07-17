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
package ghidra.app.plugin.core.analysis;

import java.util.List;

/**
 * This is a temporary analyzer, until we can get the pattern search framework up and going.
 *    This searches for patterns that are functions that have side-effects.
 */

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.search.memory.*;
import ghidra.util.task.TaskMonitor;

public class ARMPreAnalyzer extends AbstractAnalyzer {
	private static String DESCRIPTION =
		"Analyze ARM binaries for switch8_r3 functions.  This will be replaced by a general hashing algorithm next release.";

	public ARMPreAnalyzer() {
		super("ARM Pre-Pattern Analyzer", DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		Processor processor = program.getLanguage().getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("ARM")));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		String switch_fn = "\\x01\\xc0\\x5e\\xe5" + // ldrb ip,[lr,#-0x1]
			"\\x0c\\x00\\x53\\xe1" + // cmp r3,ip
			"(" + "\\x03\\x30\\xde\\x37" + // ldrbcc r3,[lr,r3]
			"\\x0c\\x30\\xde\\x27" + // ldrbcs r3,[lr,ip]
			"|" +                    // OR
			"\\x0c\\x30\\xde\\x27" + // ldrbcs r3,[lr,ip]
			"\\x03\\x30\\xde\\x37" + // ldrbcc r3,[lr,r3]
			")" + "(" + "\\x83\\xc0\\x8e\\xe0" + // add ip,lr,r3, lsl #0x1
			"\\x1c\\xff\\x2f\\xe1" + // bx ip
			"|" +                    // OR
			"\\x83\\xe0\\x8e\\xe0" + // add lr,lr,r3, lsl #0x1
			"\\x1e\\xff\\x2f\\xe1" + // bx lr
			")";

		RegExSearchData searchData = RegExSearchData.createRegExSearchData(switch_fn);

		SearchInfo searchInfo = new SearchInfo(searchData, 30, false, true, 4, false, null);

		AddressSet intersection =
			program.getMemory().getLoadedAndInitializedAddressSet().intersect(set);
		RegExMemSearcherAlgorithm searcher =
			new RegExMemSearcherAlgorithm(searchInfo, intersection, program, true);

		ListAccumulator<MemSearchResult> accumulator = new ListAccumulator<>();
		searcher.search(accumulator, monitor);
		List<MemSearchResult> results = accumulator.asList();

		// create a function here with the correct call fixup
		for (MemSearchResult result : results) {

			Address addr = result.getAddress();

			// disassemble ARM
			DisassembleCommand disassembleCommand = new DisassembleCommand(addr, null, true);
			disassembleCommand.applyTo(program);

			// create function
			CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(addr, false);
			createFunctionCmd.applyTo(program);

			// set call fixup
			Function func = program.getFunctionManager().getFunctionAt(addr);
			if (func != null) {
				func.setCallFixup("switch8_r3");
			}

			BookmarkManager bookmarkManager = program.getBookmarkManager();
			bookmarkManager.setBookmark(addr, BookmarkType.ANALYSIS, getName(),
				"Found Switch8_r3 Function");
		}

		return true;
	}
}
