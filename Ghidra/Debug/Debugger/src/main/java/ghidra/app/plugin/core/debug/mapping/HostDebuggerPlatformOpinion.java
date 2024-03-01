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

import ghidra.debug.api.platform.DebuggerPlatformMapper;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

/**
 * An opinion which just uses the trace's "host" platform, i.e., because the target created the
 * trace with the correct host language. Other mappers assume the trace language is DATA, and that
 * the real language must be mapped as a guest platform.
 */
public class HostDebuggerPlatformOpinion implements DebuggerPlatformOpinion {

	protected static class HostDebuggerPlatformMapper extends AbstractDebuggerPlatformMapper {
		public HostDebuggerPlatformMapper(PluginTool tool, Trace trace) {
			super(tool, trace);
		}

		@Override
		public CompilerSpec getCompilerSpec(TraceObject object) {
			return trace.getBaseCompilerSpec();
		}

		@Override
		public void addToTrace(long snap) {
			// Nothing to do
		}

		@Override
		public boolean canInterpret(TraceObject newFocus, long snap) {
			return true;
		}
	}

	enum Offers implements DebuggerPlatformOffer {
		HOST {
			@Override
			public String getDescription() {
				return "Host/base (Language already chosen by target)";
			}

			@Override
			public int getConfidence() {
				return 1;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				return null;
			}

			@Override
			public DebuggerPlatformMapper take(PluginTool tool, Trace trace) {
				return new HostDebuggerPlatformMapper(tool, trace);
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == HostDebuggerPlatformMapper.class;
			}
		};
	}

	@Override
	public Set<DebuggerPlatformOffer> getOffers(Trace trace, TraceObject focus, long snap,
			boolean includeOverrides) {
		return Set.of(Offers.HOST);
	}
}
