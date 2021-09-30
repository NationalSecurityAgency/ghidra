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

public class LldbX86DebuggerMappingOpinion implements DebuggerMappingOpinion {
	protected static final LanguageID LANG_ID_X86 = new LanguageID("x86:LE:32:default");
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_GCC = new CompilerSpecID("gcc");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("Visual Studio");

	protected static class LldbI386X86_64RegisterMapper extends DefaultDebuggerRegisterMapper {
		public LldbI386X86_64RegisterMapper(CompilerSpec cSpec,
				TargetRegisterContainer targetRegContainer) {
			super(cSpec, targetRegContainer, false);
		}
	}

	protected static class LldbI386MacosOffer extends AbstractDebuggerMappingOffer {
		public LldbI386MacosOffer(TargetProcess process) {
			super(process, 100, "LLDB on macos i386", LANG_ID_X86, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new LldbTargetTraceMapper(target, langID, csID, extraRegNames);
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class LldbI386LinuxOffer extends AbstractDebuggerMappingOffer {
		public LldbI386LinuxOffer(TargetProcess process) {
			super(process, 100, "LLDB on Linux i386", LANG_ID_X86, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new LldbTargetTraceMapper(target, langID, csID, extraRegNames);
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class LldbI386WindowsOffer extends AbstractLldbDebuggerMappingOffer {
		public LldbI386WindowsOffer(TargetProcess process) {
			super(process, 100, "LLDB on Cygwin/MSYS (Windows) i386", LANG_ID_X86, COMP_ID_VS,
				Set.of());
		}
	}

	protected static class LldbI386X86_64MacosOffer extends AbstractLldbDebuggerMappingOffer {
		public LldbI386X86_64MacosOffer(TargetProcess process) {
			super(process, 100, "LLDB on macos x86_64", LANG_ID_X86_64, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new LldbTargetTraceMapper(target, langID, csID, extraRegNames) {
					@Override
					protected DebuggerRegisterMapper createRegisterMapper(
							TargetRegisterContainer registers) {
						return new LldbI386X86_64RegisterMapper(cSpec, registers);
					}
				};
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class LldbI386X86_64LinuxOffer extends AbstractLldbDebuggerMappingOffer {
		public LldbI386X86_64LinuxOffer(TargetProcess process) {
			super(process, 100, "LLDB on Linux x86_64", LANG_ID_X86_64, COMP_ID_GCC, Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new LldbTargetTraceMapper(target, langID, csID, extraRegNames) {
					@Override
					protected DebuggerRegisterMapper createRegisterMapper(
							TargetRegisterContainer registers) {
						return new LldbI386X86_64RegisterMapper(cSpec, registers);
					}
				};
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected static class LldbI386X86_64WindowsOffer extends AbstractLldbDebuggerMappingOffer {
		public LldbI386X86_64WindowsOffer(TargetProcess process) {
			super(process, 100, "LLDB on Cygwin/MSYS2 (Windows) x64", LANG_ID_X86_64, COMP_ID_VS,
				Set.of());
		}

		@Override
		public DebuggerTargetTraceMapper take() {
			try {
				return new LldbTargetTraceMapper(target, langID, csID, extraRegNames) {
					@Override
					protected DebuggerRegisterMapper createRegisterMapper(
							TargetRegisterContainer registers) {
						return new LldbI386X86_64RegisterMapper(cSpec, registers);
					}
				};
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}
	}

	@Override
	public Set<DebuggerMappingOffer> offersForEnv(TargetEnvironment env, TargetProcess process) {
		if (!env.getDebugger().toLowerCase().contains("lldb")) {
			return Set.of();
		}
		String arch = env.getArchitecture();
		if (arch.startsWith("i386")) {
			return Set.of();
		}
		boolean is64Bit = arch.contains("x86-64") || arch.contains("x64-32") ||
			arch.contains("x86_64") || arch.contains("x64_32");
		String os = env.getOperatingSystem();
		Msg.info(this, "Using os=" + os + " arch=" + arch);
		if (os.contains("macos")) {
			if (is64Bit) {
				return Set.of(new LldbI386X86_64MacosOffer(process));
			}
			return Set.of(new LldbI386MacosOffer(process));
		}
		else if (os.contains("Linux") || os.contains("linux")) {
			if (is64Bit) {
				return Set.of(new LldbI386X86_64LinuxOffer(process));
			}
			return Set.of(new LldbI386LinuxOffer(process));
		}
		else if (os.contains("Cygwin")) {
			if (is64Bit) {
				return Set.of(new LldbI386X86_64WindowsOffer(process));
			}
			return Set.of(new LldbI386WindowsOffer(process));
		}
		return Set.of();
	}
}
