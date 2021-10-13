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
package ghidra.app.plugin.core.debug.platform.arm;

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.platform.gdb.DefaultGdbDebuggerMappingOpinion;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;

public class GdbArmDebuggerMappingOpinion extends DefaultGdbDebuggerMappingOpinion {

	/**
	 * An opinion-specific offer class so that offers can be recognized in unit testing
	 */
	protected static class GdbArmOffer extends GdbDefaultOffer {
		public GdbArmOffer(TargetObject target, int confidence, String description,
				LanguageCompilerSpecPair lcsp, Collection<String> extraRegNames) {
			super(target, confidence, description, lcsp, extraRegNames);
		}
	}

	/**
	 * An opinion-specific offer class so that offers can be recognized in unit testing
	 */
	protected static class GdbAArch64Offer extends GdbDefaultOffer {
		public GdbAArch64Offer(TargetObject target, int confidence, String description,
				LanguageCompilerSpecPair lcsp, Collection<String> extraRegNames) {
			super(target, confidence, description, lcsp, extraRegNames);
		}
	}

	@Override
	protected Set<DebuggerMappingOffer> offersForLanguageAndCSpec(TargetObject target, String arch,
			Endian endian, LanguageCompilerSpecPair lcsp) {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		LanguageDescription desc;
		try {
			desc = langServ.getLanguageDescription(lcsp.languageID);
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError(e);
		}
		String proc = desc.getProcessor().toString();
		if ("ARM".equalsIgnoreCase(proc)) {
			if ("Cortex".equalsIgnoreCase(desc.getVariant())) {
				return Set.of(
					new GdbArmOffer(target, 50, "ARM-Cortex/GDB for " + arch, lcsp, Set.of()));
			}
			return Set.of(new GdbArmOffer(target, 50, "ARM/GDB for " + arch, lcsp, Set.of("cpsr")));
		}
		if ("AARCH64".equalsIgnoreCase(proc)) {
			return Set.of(
				new GdbAArch64Offer(target, 50, "AARCH64/GDB for " + arch, lcsp, Set.of("cpsr")));
		}
		return Set.of();
	}
}
