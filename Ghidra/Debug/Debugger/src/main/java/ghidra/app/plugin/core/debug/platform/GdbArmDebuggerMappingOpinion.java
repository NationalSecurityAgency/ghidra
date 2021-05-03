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

public class GdbArmDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_ARM_LE_V8 = new LanguageID("ARM:LE:32:v8");
	protected static final LanguageID LANG_ID_ARM_BE_V8 = new LanguageID("ARM:BE:32:v8");
	protected static final LanguageID LANG_ID_AARCH64_LE_V8A = new LanguageID("AARCH64:LE:64:v8A");
	protected static final LanguageID LANG_ID_AARCH64_BE_V8A = new LanguageID("AARCH64:BE:64:v8A");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class GdbArmLELinuxOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbArmLELinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux arm", LANG_ID_ARM_LE_V8, COMP_ID_DEFAULT,
				Set.of("cpsr"));
		}
	}

	protected static class GdbAArch64LELinuxOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbAArch64LELinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux aarch64", LANG_ID_AARCH64_LE_V8A, COMP_ID_DEFAULT,
				Set.of("cpsr"));
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (env == null) {
			return Set.of();
		}
		if (!env.getDebugger().toLowerCase().contains("gdb")) {
			return Set.of();
		}
		String os = env.getOperatingSystem();
		if (!os.contains("Linux")) {
			return Set.of();
		}
		String endian = env.getEndian();
		if (!endian.contains("little")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		if (arch.startsWith("aarch64")) {
			return Set.of(new GdbAArch64LELinuxOffer(process));
		}
		else if (arch.startsWith("arm")) {
			return Set.of(new GdbArmLELinuxOffer(process));
		}
		return Set.of();
	}
}
