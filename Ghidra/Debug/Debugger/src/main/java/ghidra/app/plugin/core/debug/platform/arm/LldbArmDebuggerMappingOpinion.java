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

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

/**
 * TODO: How does LLDB name its target architectures? If same as GNU, use that. If not, maybe we
 * should add those external names to .ldefs? It'd be nice to have an .ldefs-based opinion that this
 * can be refactored onto.
 */
public class LldbArmDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_AARCH64 = new LanguageID("AARCH64:LE:64:v8A");
	protected static final CompilerSpecID COMP_ID_GCC = new CompilerSpecID("gcc");

	protected static class LldbI386X86_64RegisterMapper extends DefaultDebuggerRegisterMapper {
		public LldbI386X86_64RegisterMapper(CompilerSpec cSpec,
				TargetRegisterContainer targetRegContainer) {
			super(cSpec, targetRegContainer, false);
		}

		@Override
		protected String normalizeName(String name) {
			name = super.normalizeName(name);
			if ("rflags".equals(name)) {
				return "eflags";
			}
			return name;
		}
	}

	protected static class LldbAarch64MacosOffer extends DefaultDebuggerMappingOffer {
		public LldbAarch64MacosOffer(TargetProcess process) {
			super(process, 50, "AARCH64/LLDB on macos", LANG_ID_AARCH64, COMP_ID_GCC,
				Set.of("cpsr"));
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includesOverrides) {
		if (!env.getDebugger().toLowerCase().contains("lldb")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		boolean is64Bit = arch.contains("AARCH64");
		String os = env.getOperatingSystem();
		if (os.contains("macos")) {
			if (is64Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new LldbAarch64MacosOffer(process));
			}
		}
		return Set.of();
	}
}
