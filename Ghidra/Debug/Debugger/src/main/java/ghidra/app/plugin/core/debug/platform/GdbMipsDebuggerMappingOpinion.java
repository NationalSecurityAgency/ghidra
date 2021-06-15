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
package ghidra.app.plugin.core.debug.platform;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOffer;
import ghidra.app.plugin.core.debug.mapping.DebuggerMappingOpinion;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetProcess;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;

public class GdbMipsDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_MIPS32_BE = new LanguageID("MIPS:BE:32:default");
	protected static final LanguageID LANG_ID_MIPS64_BE = new LanguageID("MIPS:BE:64:default");
	protected static final LanguageID LANG_ID_MIPS64_32BE = new LanguageID("MIPS:BE:64:64-32addr");
	protected static final LanguageID LANG_ID_MIPS32_BE_R6 = new LanguageID("MIPS:BE:32:R6");
	protected static final LanguageID LANG_ID_MIPS64_BE_R6 = new LanguageID("MIPS:BE:64:R6");
	protected static final LanguageID LANG_ID_MIPS32_BE_MICRO = new LanguageID("MIPS:BE:32:micro");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class GdbMipsBELinux32DefOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux32DefOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 32-bit", LANG_ID_MIPS32_BE, COMP_ID_DEFAULT,
				Set.of());
		}
	}

	protected static class GdbMipsBELinux64DefOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux64DefOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 64-bit", LANG_ID_MIPS64_BE, COMP_ID_DEFAULT,
				Set.of());
		}
	}

	protected static class GdbMipsBELinux64_32Offer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux64_32Offer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 64/32-bit", LANG_ID_MIPS64_32BE,
				COMP_ID_DEFAULT, Set.of());
		}
	}

	protected static class GdbMipsBELinux32_R6Offer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux32_R6Offer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 32-bit R6", LANG_ID_MIPS32_BE_R6,
				COMP_ID_DEFAULT, Set.of());
		}
	}

	protected static class GdbMipsBELinux64_R6Offer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux64_R6Offer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 64-bit R6", LANG_ID_MIPS64_BE_R6,
				COMP_ID_DEFAULT, Set.of());
		}
	}

	protected static class GdbMipsBELinux32MicroOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbMipsBELinux32MicroOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux mips - 32-bit micro", LANG_ID_MIPS32_BE_MICRO,
				COMP_ID_DEFAULT, Set.of());
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
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
		if (arch.startsWith("mips:32")) {
			return Set.of(new GdbMipsBELinux32DefOffer(process));
		}
		else if (arch.startsWith("mips:64")) {
			return Set.of(new GdbMipsBELinux64DefOffer(process));
		}
		else if (arch.startsWith("mips:64_32")) {
			return Set.of(new GdbMipsBELinux64_32Offer(process));
		}
		else if (arch.startsWith("mips:32_R6")) {
			return Set.of(new GdbMipsBELinux32_R6Offer(process));
		}
		else if (arch.startsWith("mips:64_R6")) {
			return Set.of(new GdbMipsBELinux64_R6Offer(process));
		}
		else if (arch.startsWith("mips:32_micro")) {
			return Set.of(new GdbMipsBELinux32MicroOffer(process));
		}
		else if (arch.startsWith("mips")) {
			return Set.of(new GdbMipsBELinux64DefOffer(process));
		}
		return Set.of();
	}

}
