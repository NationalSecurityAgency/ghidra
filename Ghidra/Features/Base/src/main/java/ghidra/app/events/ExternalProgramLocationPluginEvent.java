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
import ghidra.program.util.ProgramLocation;

/**
 *
 * Plugin event that is generated when a tool receives an external
 * ProgramLocationToolEvent.
 */
@ToolEventName(ExternalProgramLocationPluginEvent.TOOL_EVENT_NAME) // this allows the event to be considered for tool connection
public final class ExternalProgramLocationPluginEvent extends PluginEvent {

	/**
	 * The name of this plugin event.
	 */
	public static final String NAME = "External Program Location Change";
	public static final String TOOL_EVENT_NAME = "Program Location Change";

	private ProgramLocation loc;
	private WeakReference<Program> programRef;

	/**
	 * Construct a new ProgramLocationEvent.
	 * @param src the name of the plugin that generated this event.
	 * @param loc the ProgramLocation object that contains the new location.
	 * @param program the Program for which the loc object refers.
	 */
	public ExternalProgramLocationPluginEvent(String src, ProgramLocation loc, Program program) {
		super(src, NAME);
		this.loc = loc;
		this.programRef = new WeakReference<>(program);
	}

	/**
	 * Returns the ProgramLocation stored in this event.
	 */
	public ProgramLocation getLocation() {
		return loc;
	}

	/**
	 * Returns the Program object that the location refers to.
	 */
	public Program getProgram() {
		return programRef.get();
	}

}
