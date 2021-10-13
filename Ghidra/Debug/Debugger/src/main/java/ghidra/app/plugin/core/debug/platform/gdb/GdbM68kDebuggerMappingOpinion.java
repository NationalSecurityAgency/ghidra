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
package ghidra.app.plugin.core.debug.platform.gdb;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetProcess;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

/**
 * TODO: Without architecture-specific extensions, this opinion is supplanted by the .ldefs-based
 * one. Remove me?
 */
public class GdbM68kDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_68K_BE = new LanguageID("68000:BE:32:default");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class GdbM68kBELinux32DefOffer extends DefaultDebuggerMappingOffer {
		public GdbM68kBELinux32DefOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux m68k - 32-bit", LANG_ID_68K_BE, COMP_ID_DEFAULT,
				Set.of());
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (!env.getDebugger().toLowerCase().contains("gdb")) {
			return Set.of();
		}
		String os = env.getOperatingSystem();
		if (!os.contains("Linux")) {
			return Set.of();
		}
		String endian = env.getEndian();
		if (!endian.contains("big")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		if (arch.startsWith("m68k")) {
			return Set.of(new GdbM68kBELinux32DefOffer(process));
		}
		return Set.of();
	}

}
