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

import ghidra.app.events.AbstractHighlightPluginEvent;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.program.TraceProgramView;

public class TraceHighlightPluginEvent extends AbstractHighlightPluginEvent {
	public static final String NAME = "TraceHighlight";

	private final TraceProgramView view;

	public TraceHighlightPluginEvent(String src, ProgramSelection highlight,
			TraceProgramView view) {
		super(src, NAME, highlight, view);
		this.view = Objects.requireNonNull(view);
	}

	public TraceProgramView getTraceProgramView() {
		return view;
	}
}
