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
import ghidra.app.plugin.core.debug.workflow.DisassemblyInject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class DbgengDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("windows");
	protected static final Set<DisassemblyInject> INJECTS =
		Set.of(new DbgengX64DisassemblyInject());

	protected static class DbgengX64DebuggerPlatformMapper extends DefaultDebuggerPlatformMapper {
		public DbgengX64DebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
		// TODO: Map registers: efl,rfl,rflags->eflags

		@Override
		protected Collection<DisassemblyInject> getDisassemblyInjections(TraceObject object) {
			return INJECTS;
		}
	}

	enum Offers implements DebuggerPlatformOffer {
		// TODO: X86?
		X64 {
			@Override
			public String getDescription() {
				return "Dbgeng on Windows x64";
			}

			@Override
			public int getConfidence() {
				return 100;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				return getCompilerSpec(LANG_ID_X86_64, COMP_ID_VS);
			}

			@Override
			public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
				return new DbgengX64DebuggerPlatformMapper(tool, trace, getCompilerSpec());
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == DbgengX64DebuggerPlatformMapper.class;
			}
		};
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian, boolean includeOverrides) {
		if (debugger == null || arch == null || !debugger.toLowerCase().contains("dbg")) {
			return Set.of();
		}
		boolean is64Bit = arch.contains("x86_64") || arch.contains("x64_32");
		if (!is64Bit) {
			return Set.of();
		}
		return Set.of(Offers.X64);
	}
}
