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
package ghidra.app.plugin.core.debug.mapping;

import java.util.Set;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

public class TestDebuggerPlatformOpinion extends AbstractDebuggerPlatformOpinion {

	protected static class TestDebuggerPlatformMapper extends DefaultDebuggerPlatformMapper {
		public TestDebuggerPlatformMapper(PluginTool tool, Trace trace, CompilerSpec cSpec) {
			super(tool, trace, cSpec);
		}
	}

	enum Offers implements DebuggerPlatformOffer {
		ARM_V8_LE("Test armv8le", "ARM:LE:32:v8", "default"),
		X86_64("Test x86-64", "x86:LE:64:default", "gcc");

		private final String description;
		private final LanguageCompilerSpecPair lcsp;

		private Offers(String description, String langID, String cSpecID) {
			this.description = description;
			this.lcsp = new LanguageCompilerSpecPair(langID, cSpecID);
		}

		@Override
		public String getDescription() {
			return description;
		}

		@Override
		public int getConfidence() {
			return 1;
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			try {
				return lcsp.getCompilerSpec();
			}
			catch (LanguageNotFoundException | CompilerSpecNotFoundException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
			return new TestDebuggerPlatformMapper(tool, trace, getCompilerSpec());
		}

		@Override
		public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
			return mapper.getClass() == TestDebuggerPlatformMapper.class;
		}
	}

	@Override
	protected Set<DebuggerPlatformOffer> getOffers(TraceObject object, long snap,
			TraceObject env, String debugger, String arch, String os, Endian endian,
			boolean includeOverrides) {
		if (!"test".equals(debugger)) {
			return Set.of();
		}
		if ("armv8le".equals(arch)) {
			return Set.of(Offers.ARM_V8_LE);
		}
		if ("x86-64".equals(arch)) {
			return Set.of(Offers.X86_64);
		}
		return Set.of();
	}
}
