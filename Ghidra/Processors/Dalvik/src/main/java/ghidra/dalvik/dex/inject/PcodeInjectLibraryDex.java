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

	private InjectPayloadDexParameters paramPayload = null;
	private InjectPayloadDexRange rangePayload = null;

	public PcodeInjectLibraryDex(SleighLanguage l) {
		super(l);
	}

	@Override
	public InjectPayload getPayload(int type, String name, Program program,
			String context) {
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
			if (paramPayload == null) {
				paramPayload = new InjectPayloadDexParameters();
			}
			return paramPayload;
		}
		else if (type == InjectPayload.CALLOTHERFIXUP_TYPE && name.equals("moveRangeToIV")) {
			if (rangePayload == null) {
				rangePayload = new InjectPayloadDexRange();
			}
			return rangePayload;
		}

		return super.getPayload(type, name, program, context);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new ConstantPoolDex(program);
	}

}
