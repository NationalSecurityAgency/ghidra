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
package ghidra.pcode.exec;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcodeCPort.slghsymbol.UserOpSymbol;
import ghidra.program.model.pcode.PcodeOp;

public class SleighProgram {
	protected final SleighLanguage language;
	protected final List<PcodeOp> code;
	protected final Map<Integer, String> useropNames = new HashMap<>();

	protected SleighProgram(SleighLanguage language, List<PcodeOp> code,
			Map<Integer, UserOpSymbol> useropSymbols) {
		this.language = language;
		this.code = code;
		int langOpCount = language.getNumberOfUserDefinedOpNames();
		for (Map.Entry<Integer, UserOpSymbol> ent : useropSymbols.entrySet()) {
			int index = ent.getKey();
			if (index < langOpCount) {
				useropNames.put(index, language.getUserDefinedOpName(index));
			}
			else {
				useropNames.put(index, ent.getValue().getName());
			}
		}
	}

	public SleighLanguage getLanguage() {
		return language;
	}

	public <T> void execute(PcodeExecutor<T> executor, SleighUseropLibrary<T> library) {
		executor.execute(this, library);
	}

	protected String getHead() {
		return getClass().getSimpleName();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("<" + getHead() + ":");
		for (PcodeOp op : code) {
			sb.append("\n  " + op.getSeqnum() + ": " + op);
		}
		sb.append("\n>");
		return sb.toString();
	}
}
