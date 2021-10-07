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
public class GdbPowerPCDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_PPC32_BE = new LanguageID("PowerPC:BE:32:default");
	protected static final LanguageID LANG_ID_PPC64_BE = new LanguageID("PowerPC:BE:64:default");
	protected static final LanguageID LANG_ID_PPC64_BE_A2 =
		new LanguageID("PowerPC:BE:64:A2-32addr");
	protected static final LanguageID LANG_ID_PPC64_BE_A2ALT =
		new LanguageID("PowerPC:BE:64:A2ALT-32addr");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class GdbPowerPCBE32DefLinuxOffer extends DefaultDebuggerMappingOffer {
		public GdbPowerPCBE32DefLinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux PowerPC - 32-bit", LANG_ID_PPC32_BE, COMP_ID_DEFAULT,
				Set.of());
		}
	}

	protected static class GdbPowerPCBE64DefLinuxOffer extends DefaultDebuggerMappingOffer {
		public GdbPowerPCBE64DefLinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux PowerPC - 64-bit", LANG_ID_PPC64_BE, COMP_ID_DEFAULT,
				Set.of());
		}
	}

	protected static class GdbPowerPCBE64A2LinuxOffer extends DefaultDebuggerMappingOffer {
		public GdbPowerPCBE64A2LinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux PowerPC - 64-bit A2", LANG_ID_PPC64_BE_A2,
				COMP_ID_DEFAULT, Set.of());
		}
	}

	protected static class GdbPowerPCBA64A2AltLinuxOffer extends DefaultDebuggerMappingOffer {
		public GdbPowerPCBA64A2AltLinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux PowerPC - 64-bit A2 ALT", LANG_ID_PPC64_BE_A2ALT,
				COMP_ID_DEFAULT, Set.of());
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
		if (arch.startsWith("powerpc:32")) {
			return Set.of(new GdbPowerPCBE32DefLinuxOffer(process));
		}
		else if (arch.startsWith("powerpc:A2")) {
			return Set.of(new GdbPowerPCBE64A2LinuxOffer(process));
		}
		else if (arch.startsWith("powerpc:A2-Alt")) {
			return Set.of(new GdbPowerPCBA64A2AltLinuxOffer(process));
		}
		else if (arch.startsWith("powerpc")) {
			return Set.of(new GdbPowerPCBE64DefLinuxOffer(process));
		}
		return Set.of();
	}
}
