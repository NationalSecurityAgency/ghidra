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
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

public abstract class AbstractLocationPluginEvent extends PluginEvent {

	private final ProgramLocation location;
	private final WeakReference<Program> programRef;

	/**
	 * Construct a new event
	 * 
	 * @param sourceName the name of the plugin that generated this event.
	 * @param eventName the name of the event type
	 * @param location the new location
	 * @param program the program for which the location object refers.
	 */
	protected AbstractLocationPluginEvent(String sourceName, String eventName,
			ProgramLocation location, Program program) {
		super(sourceName, eventName);

		// don't allow a null for a program location
		if (location == null) {
			NullPointerException exc = new NullPointerException(
				"Null ProgramLocation passed to create a Plugin event");
			Msg.showError(this,
				null, "Error",
				"Null LocationEvent being created.  Trace and remove this problem", exc);
		}
		this.location = location;
		this.programRef = new WeakReference<Program>(program);
	}

	/**
	 * Get the location stored in this event.
	 * 
	 * @return the location
	 */
	public ProgramLocation getLocation() {
		return location;
	}

	/**
	 * Get the program that the location refers to.
	 * 
	 * @return the program
	 */
	public Program getProgram() {
		return programRef.get();
	}

	@Override
	protected String getDetails() {
		if (location != null) {
			return location.getClass().getName() + " addr==> " + location.getAddress() + "\n";
		}
		return super.getDetails();
	}
}
