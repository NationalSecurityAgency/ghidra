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
package ghidra.dalvik.dex.inject;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

public class PcodeInjectLibraryDex extends PcodeInjectLibrary {

	public PcodeInjectLibraryDex(SleighLanguage l) {
		super(l);
	}

	public PcodeInjectLibraryDex(PcodeInjectLibraryDex op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryDex(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectPayloadDexParameters(name, sourceName);
		}
		else if (tp == InjectPayload.CALLOTHERFIXUP_TYPE && name.equals("moveRangeToIV")) {
			return new InjectPayloadDexRange();
		}
		return super.allocateInject(sourceName, name, tp);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new ConstantPoolDex(program);
	}
}
