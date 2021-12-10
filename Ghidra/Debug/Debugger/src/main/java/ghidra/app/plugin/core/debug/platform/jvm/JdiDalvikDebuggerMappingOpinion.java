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
package ghidra.app.plugin.core.debug.platform.jvm;

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;

public class JdiDalvikDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_DALVIK = new LanguageID("Dalvik:LE:32:default");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("default");

	protected static final Set<String> DALVIK_VM_NAMES = Set.of("Dalvik");

	protected static class DalvikDebuggerTargetTraceMapper
			extends DefaultDebuggerTargetTraceMapper {
		public DalvikDebuggerTargetTraceMapper(TargetObject target, LanguageID langID,
				CompilerSpecID csId, Collection<String> extraRegNames)
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			super(target, langID, csId, extraRegNames);
		}

		@Override
		protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
			return new DefaultDebuggerMemoryMapper(language, memory.getModel());
		}

		@Override
		protected DebuggerRegisterMapper createRegisterMapper(TargetRegisterContainer registers) {
			return new DefaultDebuggerRegisterMapper(cSpec, registers, false);
		}
	}

	protected static class DalvikDebuggerMappingOffer extends DefaultDebuggerMappingOffer {
		public DalvikDebuggerMappingOffer(TargetProcess process) {
			super(process, 100, "Dalvik Virtual Machine", LANG_ID_DALVIK, COMP_ID_VS, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper createMapper()
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			return new DalvikDebuggerTargetTraceMapper(target, langID, csID, extraRegNames);
		}
	}

	protected static boolean containsRecognizedJvmName(String name) {
		return DALVIK_VM_NAMES.stream().anyMatch(name::contains);
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process,
			boolean includeOverrides) {
		if (!env.getDebugger().contains("Java Debug Interface")) {
			return Set.of();
		}
		if (!containsRecognizedJvmName(env.getArchitecture())) {
			return Set.of();
		}
		// NOTE: Not worried about JRE version
		return Set.of(new DalvikDebuggerMappingOffer(process));
	}
}
