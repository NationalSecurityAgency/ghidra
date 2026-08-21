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
package ghidra.app.plugin.core.debug.event;

import java.util.Objects;

import ghidra.app.events.AbstractSelectionPluginEvent;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

public class TraceSelectionPluginEvent extends AbstractSelectionPluginEvent {
	public static final String NAME = "TraceSelection";

	private final TraceProgramView view;

	public TraceSelectionPluginEvent(String src, ProgramSelection selection,
			TraceProgramView view) {
		super(src, NAME, selection, view);
		this.view = Objects.requireNonNull(view);
	}

	public TraceProgramView getTraceProgramView() {
		return view;
	}
}
