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

import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * This plugin event class provides program location information.
 * 
 * <p>
 * The event is fired when a plugin's program location has changed. Typically, a plugin does not
 * actually generate the event unless it is processing some user action, e.g., the user mouse clicks
 * somewhere on a plugin component to cause the program location to change.
 */
public final class ProgramLocationPluginEvent extends AbstractLocationPluginEvent {

	/**
	 * The name of this plugin event.
	 */
	public static final String NAME = "ProgramLocationChange";

	/**
	 * Construct a new ProgramLocationEvent.
	 * 
	 * @param src the name of the plugin that generated this event.
	 * @param loc the ProgramLocation object that contains the new location.
	 * @param program the Program for which the loc object refers.
	 */
	public ProgramLocationPluginEvent(String src, ProgramLocation loc, Program program) {
		super(src, NAME, loc, program);
	}
}
