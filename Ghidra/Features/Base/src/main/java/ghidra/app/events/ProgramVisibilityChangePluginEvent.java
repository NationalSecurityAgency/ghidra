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
package ghidra.app.events;

import java.lang.ref.WeakReference;

import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.ToolEventName;
import ghidra.program.model.listing.Program;

/**
 * Event for telling a tool (program mgr) to open a program
 *
 */
@ToolEventName(ProgramVisibilityChangePluginEvent.TOOL_EVENT_NAME) // this allows the event to be considered for tool connection
public class ProgramVisibilityChangePluginEvent extends PluginEvent {

	static final String NAME = "Open Program";
	static final String TOOL_EVENT_NAME = "Open/Close Program";

	private WeakReference<Program> programRef;
	private boolean isVisible;

	/**
	 * Constuct a new plugin event.
	 * @param source name of the plugin that created this event
	 * @param p the program associated with this event
	 */
	public ProgramVisibilityChangePluginEvent(String source, Program p, boolean isVisible) {
		super(source, NAME);
		this.isVisible = isVisible;
		this.programRef = new WeakReference<>(p);
	}

	/**
	 * Return the program on this event.
	 * @return null if the event if for a program closing.
	 */
	public Program getProgram() {
		return programRef.get();
	}

	/**
	 * Returns true if program is currently in a visible state.
	 */
	public boolean isProgramVisible() {
		return isVisible;
	}

}
