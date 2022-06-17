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
package ghidra.app.plugin.core.debug.platform.frida;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

/**
 * TODO: How does Frida name its target architectures? If same as GNU, use that. If not, maybe we
 * should add those external names to .ldefs? It'd be nice to have an .ldefs-based opinion that this
 * can be refactored onto.
 */
public class FridaArmDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_AARCH64 = new LanguageID("AARCH64:LE:64:v8A");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");

	protected static class FridaI386X86_64RegisterMapper extends DefaultDebuggerRegisterMapper {
		public FridaI386X86_64RegisterMapper(CompilerSpec cSpec,
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

	protected static class FridaAarch64MacosOffer extends DefaultDebuggerMappingOffer {
		public FridaAarch64MacosOffer(TargetProcess process) {
			super(process, 50, "AARCH64/Frida on macos", LANG_ID_AARCH64, COMP_ID_DEFAULT,
				Set.of("cpsr"));
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetObject target,
			boolean includesOverrides) {
		if (!(target instanceof TargetProcess)) {
			return Set.of();
		}
		if (!env.getDebugger().toLowerCase().contains("frida")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		boolean is64Bit =
			arch.contains("AARCH64") || arch.contains("arm64") || arch.contains("arm");
		String os = env.getOperatingSystem();
		if (os.contains("macos")) {
			if (is64Bit) {
				Msg.info(this, "Using os=" + os + " arch=" + arch);
				return Set.of(new FridaAarch64MacosOffer((TargetProcess) target));
			}
		}
		return Set.of();
	}
}
