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
package wasm.pcode;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary {

	public PcodeInjectLibraryWasm(SleighLanguage l) {
		super(l);
	}

	public PcodeInjectLibraryWasm(PcodeInjectLibraryWasm op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryWasm(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			switch (name) {
			case "funcEntryCallOther":
				return new InjectPayloadWasmEntry(sourceName);
			case "popCallOther":
			case "callEpilogueCallOther":
			case "callPrologueCallOther":
				return new InjectPayloadWasmPop(sourceName);
			case "pushCallOther":
				return new InjectPayloadWasmPush(sourceName);
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
