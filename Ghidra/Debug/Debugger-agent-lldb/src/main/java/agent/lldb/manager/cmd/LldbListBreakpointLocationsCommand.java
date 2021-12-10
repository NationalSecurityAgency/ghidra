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
package agent.lldb.manager.cmd;

import java.util.HashMap;
import java.util.Map;

import SWIG.SBBreakpoint;
import SWIG.SBBreakpointLocation;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.impl.LldbManagerImpl;

/**
 * Implementation of {@link LldbProcess#listBreakpoints()}
 */
public class LldbListBreakpointLocationsCommand
		extends AbstractLldbCommand<Map<String, SBBreakpointLocation>> {

	private Map<String, SBBreakpointLocation> updatedLocations = new HashMap<>();
	protected final SBBreakpoint spec;

	public LldbListBreakpointLocationsCommand(LldbManagerImpl manager, SBBreakpoint spec) {
		super(manager);
		this.spec = spec;
	}

	@Override
	public Map<String, SBBreakpointLocation> complete(LldbPendingCommand<?> pending) {
		return updatedLocations;
	}

	@Override
	public void invoke() {
		updatedLocations.clear();
		long n = spec.GetNumResolvedLocations();
		for (int i = 0; i < n; i++) {
			SBBreakpointLocation loc = spec.GetLocationAtIndex(i);
			updatedLocations.put(DebugClient.getId(loc), loc);
		}
	}
}
