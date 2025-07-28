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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.util.Collection;
import java.util.stream.Collectors;

import docking.DefaultActionContext;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;

public class DebuggerBreakpointLocationsActionContext extends DefaultActionContext {
	private final Collection<BreakpointLocationRow> selection;

	public DebuggerBreakpointLocationsActionContext(Collection<BreakpointLocationRow> selection) {
		this.selection = selection;
	}

	public Collection<BreakpointLocationRow> getSelection() {
		return selection;
	}

	public Collection<TraceBreakpointLocation> getLocations() {
		return selection.stream().map(row -> row.getTraceBreakpoint()).collect(Collectors.toList());
	}
}
