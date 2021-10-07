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
package ghidra.app.plugin.core.debug.platform.dbgeng;

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;

public class DbgengX64DebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("windows");

	protected static class DbgI386X86_64RegisterMapper extends LargestSubDebuggerRegisterMapper {
		public DbgI386X86_64RegisterMapper(CompilerSpec cSpec,
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

	protected static class DbgI386X86_64WindowsTraceMapper
			extends DefaultDebuggerTargetTraceMapper {
		public DbgI386X86_64WindowsTraceMapper(TargetObject target, LanguageID langID,
				CompilerSpecID csId, Collection<String> extraRegNames)
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			super(target, langID, csId, extraRegNames);
		}

		@Override
		protected DebuggerRegisterMapper createRegisterMapper(TargetRegisterContainer registers) {
			return new DbgI386X86_64RegisterMapper(cSpec, registers);
		}
	}

	protected static class DbgI386X86_64WindowsOffer extends DefaultDebuggerMappingOffer {
		public DbgI386X86_64WindowsOffer(TargetProcess process) {
			super(process, 100, "Dbgeng on Windows x64", LANG_ID_X86_64, COMP_ID_VS, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper createMapper()
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			return new DbgI386X86_64WindowsTraceMapper(target, langID, csID, extraRegNames);
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (env == null || !env.getDebugger().toLowerCase().contains("dbg")) {
			return Set.of();
		}
		boolean is64Bit =
			env.getArchitecture().contains("x86_64") || env.getArchitecture().contains("x64_32");
		if (is64Bit) {
			return Set.of(new DbgI386X86_64WindowsOffer(process));
		}
		return null;
	}
}
