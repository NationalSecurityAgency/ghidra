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

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.dbg.target.*;
import ghidra.program.model.lang.*;
import ghidra.util.Msg;

public class GdbX86DebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_X86 = new LanguageID("x86:LE:32:default");
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_GCC = new CompilerSpecID("gcc");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("Visual Studio");

	protected static class GdbI386X86_64RegisterMapper extends DefaultDebuggerRegisterMapper {
		public GdbI386X86_64RegisterMapper(CompilerSpec cSpec,
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

	protected static class GdbI386LinuxOffer extends AbstractDebuggerMappingOffer {
		public GdbI386LinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux i386", LANG_ID_X86, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new GdbTargetTraceMapper(target, langID, csID, extraRegNames);
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class GdbI386WindowsOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbI386WindowsOffer(TargetProcess process) {
			super(process, 100, "GDB on Cygwin/MSYS (Windows) i386", LANG_ID_X86, COMP_ID_VS,
				Set.of());
		}
	}

	protected static class GdbI386X86_64LinuxOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbI386X86_64LinuxOffer(TargetProcess process) {
			super(process, 100, "GDB on Linux x86_64", LANG_ID_X86_64, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new GdbTargetTraceMapper(target, langID, csID, extraRegNames) {
					@Override
					protected DebuggerRegisterMapper createRegisterMapper(
							TargetRegisterContainer registers) {
						return new GdbI386X86_64RegisterMapper(cSpec, registers);
					}
				};
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class GdbI386X86_64WindowsOffer extends AbstractGdbDebuggerMappingOffer {
		public GdbI386X86_64WindowsOffer(TargetProcess process) {
			super(process, 100, "GDB on Cygwin/MSYS2 (Windows) x64", LANG_ID_X86_64, COMP_ID_VS,
				Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new GdbTargetTraceMapper(target, langID, csID, extraRegNames) {
					@Override
					protected DebuggerRegisterMapper createRegisterMapper(
							TargetRegisterContainer registers) {
						return new GdbI386X86_64RegisterMapper(cSpec, registers);
					}
				};
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (!env.getDebugger().toLowerCase().contains("gdb")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		if (!arch.startsWith("i386")) {
			return Set.of();
		}
		boolean is64Bit = arch.contains("x86-64") || arch.contains("x64-32");
		String os = env.getOperatingSystem();
		Msg.info(this, "Using os=" + os + " arch=" + arch);
		if (os.contains("Linux")) {
			if (is64Bit) {
				return Set.of(new GdbI386X86_64LinuxOffer(process));
			}
			else {
				return Set.of(new GdbI386LinuxOffer(process));
			}
		}
		else if (os.contains("Cygwin")) {
			if (is64Bit) {
				return Set.of(new GdbI386X86_64WindowsOffer(process));
			}
			else {
				return Set.of(new GdbI386WindowsOffer(process));
			}
		}
		return Set.of();
	}
}
