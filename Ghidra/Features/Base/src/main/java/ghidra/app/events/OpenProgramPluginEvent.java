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
 * <p>
 * This event shares a common tool-event name with the {@link OpenProgramPluginEvent} 
 * so that they have a single shared tool connection.
 */
@ToolEventName(OpenProgramPluginEvent.TOOL_EVENT_NAME) // this allows the event to be considered for tool connection
public class OpenProgramPluginEvent extends PluginEvent {

	static final String NAME = "Open Program";
	static final String TOOL_EVENT_NAME = "Open/Close Program";

	private WeakReference<Program> programRef;

	/**
	 * Constuct a new plugin event.
	 * @param source name of the plugin that created this event
	 * @param p the program associated with this event
	 */
	public OpenProgramPluginEvent(String source, Program p) {
		super(source, NAME);
		this.programRef = new WeakReference<>(p);
	}

	/**
	 * Return the program on this event.
	 * @return null if the event if for a program closing.
	 */
	public Program getProgram() {
		return programRef.get();
	}

}
