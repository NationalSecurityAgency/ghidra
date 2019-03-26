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
//Search for instructions with a given PCode operation.
//@category Languages

import ghidra.app.plugin.languages.sleigh.PcodeOpEntryVisitor;
import ghidra.app.plugin.languages.sleigh.SleighLanguages;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.NumericUtilities;

/**
 * This is a demonstration script to show how to query SLEIGH-based languages for various features.
 * It simply dumps a list of constructor line numbers and patterns for instructions that have a
 * RETURN PCode operation. If performed over every supported language and stored into a database,
 * this could be used to find all supported languages having a "ret" or similar instruction with a
 * given encoding.
 */
public class LanguagesAPIDemoScript extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// The API is accessed using a callback, so instantiate the class to receive that callback.
		PcodeOpEntryVisitor visitor = new DumpPcodeOps();
		// Perform the iteration with the given callback visitor.
		int result = SleighLanguages.traverseAllPcodeOps(
			(SleighLanguage) currentProgram.getLanguage(), visitor);
		println("Result: " + result);
	}

	/**
	 * This class receives a callback for each PCode op template visited. NOTE: if a constructor is
	 * effectively a NOP (no PCode ops), it will still generate exactly one callback, where op is
	 * null.
	 */
	class DumpPcodeOps implements PcodeOpEntryVisitor {
		@Override
		public int visit(SubtableSymbol subtable, DisjointPattern pattern, Constructor cons,
				OpTpl op) {
			// Be nice :)
			if (monitor.isCancelled()) {
				return TERMINATE;
			}

			// Consider only root constructors
			if (!"instruction".equals(subtable.getName())) {
				return CONTINUE;
			}

			// Check any opcode is a return, and do something interesting if it does.
			if (op != null && op.getOpcode() == PcodeOp.RETURN) {
				byte[] whole = pattern.getWholeInstructionBytes();
				String pat = NumericUtilities.convertBytesToString(whole);
				println(subtable.getName() + " (" + pat + "," + cons + "): " + op);
			}
			return CONTINUE;
		}
	}
}
