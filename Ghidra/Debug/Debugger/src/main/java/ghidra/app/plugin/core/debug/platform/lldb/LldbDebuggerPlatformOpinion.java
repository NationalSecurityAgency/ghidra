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
package ghidra.app.plugin.core.debug.platform.lldb;

import java.util.Set;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class LldbDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {
	protected static final LanguageID LANG_ID_AARCH64 = new LanguageID("AARCH64:LE:64:v8A");
	protected static final LanguageID LANG_ID_X86 = new LanguageID("x86:LE:32:default");
	protected static final LanguageID LANG_ID_X86_64 = new LanguageID("x86:LE:64:default");
	protected static final CompilerSpecID COMP_ID_DEFAULT = new CompilerSpecID("default");
	protected static final CompilerSpecID COMP_ID_GCC = new CompilerSpecID("gcc");
	protected static final CompilerSpecID COMP_ID_VS = new CompilerSpecID("windows");

	protected static class LldbDebuggerPlatformMapper
			extends DefaultDebuggerPlatformMapper {
		public LldbDebuggerPlatformMapper(PluginTool tool, Trace trace,
				CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
		// TODO: Map registers: rflags<->eflags for x86_64?
	}

	enum Offers implements DebuggerPlatformOffer {
		AARCH64_MACOS("LLDB on macOS Apple Silicon", LANG_ID_AARCH64, COMP_ID_DEFAULT),
		I386_LINUX("LLDB on Linux i386", LANG_ID_X86, COMP_ID_GCC),
		I386_MACOS("LLDB on macOS i386", LANG_ID_X86, COMP_ID_GCC),
		I386_WINDOWS("LLDB on Windows x86", LANG_ID_X86, COMP_ID_VS),
		X86_64_LINUX("LLDB on Linux x86_64", LANG_ID_X86_64, COMP_ID_GCC),
		X86_64_MACOS("LLDB on macOS x86_64", LANG_ID_X86_64, COMP_ID_GCC),
		X86_64_WINDOWS("LLDB on Windows x64", LANG_ID_X86_64, COMP_ID_VS);

		final String description;
		final LanguageID langID;
		final CompilerSpecID cSpecID;

		private Offers(String description, LanguageID langID, CompilerSpecID cSpecID) {
			this.description = description;
			this.langID = langID;
			this.cSpecID = cSpecID;
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public int getConfidence() {
			return 100;
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			return getCompilerSpec(langID, cSpecID);
		}

		@Override
		public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
			// TODO: May need these per offer
			return new LldbDebuggerPlatformMapper(tool, trace, getCompilerSpec());
		}
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap, TraceObject env,
			String debugger, String arch, String os, Endian endian) {
		if (debugger == null || arch == null ||
			os == null | !debugger.toLowerCase().contains("lldb")) {
			return Set.of();
		}
		String lcOS = os.toLowerCase();
		boolean isLinux = lcOS.contains("linux");
		boolean isMacOS = lcOS.contains("darwin") || lcOS.contains("macos");
		boolean isWindows = lcOS.contains("windows");
		String lcArch = arch.toLowerCase();
		// "arm" subsumes "arm64"
		boolean isARM = lcArch.contains("aarch64") || lcArch.contains("arm");
		boolean isI386 = lcArch.contains("ia32") || lcArch.contains("x86-32") ||
			lcArch.contains("x86_32") || lcArch.contains("i386");
		boolean isX86_64 = lcArch.contains("x64") || lcArch.contains("x86-64") ||
			lcArch.contains("x86_64") || lcArch.contains("x64-32") || lcArch.contains("x64_32");
		// TODO: i686? I'd think 32-bit,
		// but it was listed as 64-bit in LldbX86DebuggerMappingOpinion

		if (isLinux) {
			if (isI386) {
				return Set.of(Offers.I386_LINUX);
			}
			if (isX86_64) {
				return Set.of(Offers.X86_64_LINUX);
			}
		}
		if (isMacOS) {
			if (isARM) {
				return Set.of(Offers.AARCH64_MACOS);
			}
			if (isI386) {
				return Set.of(Offers.I386_MACOS);
			}
			if (isX86_64) {
				return Set.of(Offers.X86_64_MACOS);
			}
		}
		if (isWindows) {
			if (isI386) {
				return Set.of(Offers.I386_WINDOWS);
			}
			if (isX86_64) {
				return Set.of(Offers.X86_64_WINDOWS);
			}
		}
		return Set.of();
	}
}
