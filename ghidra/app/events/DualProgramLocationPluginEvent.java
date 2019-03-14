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

import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.ToolEventName;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * This plugin event class provides program location information for
 * plugins that send information to two or more tools containing associated addresses.
 */
@ToolEventName(DualProgramLocationPluginEvent.NAME) // this allows the event to be considered for tool connection
public final class DualProgramLocationPluginEvent extends PluginEvent {

	/**
	 * Name of this plugin event.
	 */
	public static final String NAME = "DualProgramLocation";

	private ProgramLocation loc;
	private String programName;

	/**
	 * Construct a new DualProgramLocationPluginEvent.
	 * @param src the name of the plugin that generated this event.
	 * @param loc the ProgramLocation object that contains the new location.
	 * @param programName the name of the program for which the loc object refers.
	 */
	public DualProgramLocationPluginEvent(String src, ProgramLocation loc, String programName) {
		super(src, NAME);
		this.loc = loc;
		this.programName = programName;
	}

	/**
	 * Construct a new DualProgramLocationPluginEvent.
	 * @param src the name of the plugin that generated this event.
	 * @param loc the ProgramLocation object that contains the new location.
	 * @param program the program for which the loc object refers.
	 */
	public DualProgramLocationPluginEvent(String src, ProgramLocation loc, Program program) {
		super(src, NAME);
		this.loc = loc;
		this.programName = program.getName();
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
	public String getProgramName() {
		return programName;
	}

}
