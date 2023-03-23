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
package ghidra.app.plugin.core.debug.mapping.legacy;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.workflow.DisassemblyInject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.lifecycle.Transitional;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.util.classfinder.ClassSearcher;

/**
 * An opinion which retains the front-end functionality when using the mapped recorder, i.e., when
 * displaying non-object-based traces.
 */
@Transitional
public class LegacyDebuggerPlatformOpinion implements DebuggerPlatformOpinion {

	protected static class LegacyDebuggerPlatformMapper extends AbstractDebuggerPlatformMapper {
		public LegacyDebuggerPlatformMapper(PluginTool tool, Trace trace) {
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

		@Override
		protected Collection<DisassemblyInject> getDisassemblyInjections(TraceObject object) {
			// Track an injects set using a listener instead?
			return ClassSearcher.getInstances(DisassemblyInject.class)
					.stream()
					.filter(i -> i.isApplicable(trace))
					.sorted(Comparator.comparing(i -> i.getPriority()))
					.collect(Collectors.toList());
		}
	}

	enum Offers implements DebuggerPlatformOffer {
		LEGACY {
			@Override
			public String getDescription() {
				return "Legacy (Already mapped by recorder)";
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
				return new LegacyDebuggerPlatformMapper(tool, trace);
			}

			@Override
			public boolean isCreatorOf(DebuggerPlatformMapper mapper) {
				return mapper.getClass() == LegacyDebuggerPlatformMapper.class;
			}
		};
	}

	@Override
	public Set<DebuggerPlatformOffer> getOffers(Trace trace, TraceObject focus, long snap,
			boolean includeOverrides) {
		if (trace.getObjectManager().getRootObject() != null) {
			return Set.of();
		}
		return Set.of(Offers.LEGACY);
	}
}
