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
// Produces a list of instructions whose pcode contains a CALLOTHER pcode op.  The list is
// sorted by number of occurrences of an instruction. When run headlessly, the list is displayed 
// each time a program is processed and the counts are cumulative.
// @category sleigh

import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.PcodeOp;

public class CallotherCensusScript extends GhidraScript {

	public static Map<String, CountAndLocationInfo> instCountMap = new HashMap<>();

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			popup("This script requires an active current program.");
			return;
		}
		if (!isRunningHeadless()) {
			instCountMap.clear();
		}

		InstructionIterator instIter = currentProgram.getListing().getInstructions(true);
		while (instIter.hasNext()) {
			monitor.checkCancelled();
			Instruction inst = instIter.next();
			for (PcodeOp op : inst.getPcode()) {
				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					String mnemonic = inst.getMnemonicString();
					CountAndLocationInfo countInfo = instCountMap.computeIfAbsent(mnemonic,
						s -> new CountAndLocationInfo(s,
							currentProgram.getDomainFile().getPathname() + " " +
								inst.getAddress()));
					countInfo.incrementCount();
				}
			}
		}
		instCountMap.values().stream().sorted().forEach(x -> printf("%s\n", x.toString()));

	}

	class CountAndLocationInfo implements Comparable<CountAndLocationInfo> {
		private String mnemonic;
		private String firstOccurrence;
		private Integer count;

		public CountAndLocationInfo(String mnemonic, String firstOccurrence) {
			this.mnemonic = mnemonic;
			this.firstOccurrence = firstOccurrence;
			count = 0;
		}

		public void incrementCount() {
			count += 1;
		}

		@Override
		public String toString() {
			return mnemonic + " " + count.toString() + " " + firstOccurrence;
		}

		@Override
		public int compareTo(CountAndLocationInfo o) {
			return -Integer.compare(count, o.count);
		}

	}

}
