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
package ghidra.app.util.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.lang.PcodeInjectLibrary;

/**
 * NDS32-specific pcode-injection library.
 *
 * <p>Provides one fixup: {@code ex9} (the {@code ex9.it} instruction). The
 * sleigh emits a placeholder {@code ex9(imm)} CALLOTHER; this library
 * substitutes the pcode of the instruction stored at {@code ITB[imm]} so
 * the decompiler and emulator can see the actual semantics rather than an
 * opaque user-op.
 */
public class PcodeInjectLibraryNDS32 extends PcodeInjectLibrary {
	public static final String EX9 = "ex9";
	public static final String SOURCENAME = "NDS32";

	private final Map<String, InjectPayloadCallother> implementedOps;

	public PcodeInjectLibraryNDS32(SleighLanguage l) {
		super(l);
		implementedOps = new HashMap<>();
		implementedOps.put(EX9, new InjectEX9IT(SOURCENAME, l));
		uniqueBase += 0x100;
	}

	public PcodeInjectLibraryNDS32(PcodeInjectLibraryNDS32 op2) {
		super(op2);
		implementedOps = op2.implementedOps;
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryNDS32(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			InjectPayloadCallother payload = implementedOps.get(name);
			if (payload != null) {
				return payload;
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
