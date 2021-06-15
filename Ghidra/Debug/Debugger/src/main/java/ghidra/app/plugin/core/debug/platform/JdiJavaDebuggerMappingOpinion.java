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

import java.util.Collection;
import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;

public class JdiJavaDebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_JAVA = new LanguageID("JVM:BE:32:default");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("default");

	// TODO: Catalog other VMs that are Java, but not Dalvik
	protected static final Set<String> JVM_NAMES = Set.of("OpenJDK");

	protected static class JavaDebuggerTargetTraceMapper extends AbstractDebuggerTargetTraceMapper {
		public JavaDebuggerTargetTraceMapper(TargetObject target, LanguageID langID,
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

	protected static class JavaDebuggerMappingOffer extends AbstractDebuggerMappingOffer {
		public JavaDebuggerMappingOffer(TargetProcess process) {
			super(process, 100, "Java Virtual Machine", LANG_ID_JAVA, COMP_ID_VS, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new JavaDebuggerTargetTraceMapper(target, langID, csID, extraRegNames);
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static boolean containsRecognizedJvmName(String name) {
		return JVM_NAMES.stream().anyMatch(name::contains);
	}

	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (!env.getDebugger().contains("Java Debug Interface")) {
			return Set.of();
		}
		if (!containsRecognizedJvmName(env.getArchitecture())) {
			return Set.of();
		}
		// NOTE: Not worried about JRE version
		return Set.of(new JavaDebuggerMappingOffer(process));
	}
}
