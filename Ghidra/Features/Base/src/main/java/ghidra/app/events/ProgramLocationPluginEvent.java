/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.lang.ref.WeakReference;

/**
 * This plugin event class provides program location information.
 * The event is fired when a plugin's program location has changed.
 * Typically, a plugin does not actually generate the event unless it is 
 * processing some user action, 
 * e.g., the user mouse clicks somewhere on a plugin component to cause
 * the program location to change.
 */
public final class ProgramLocationPluginEvent extends PluginEvent {

	/**
	 * The name of this plugin event.
	 */
    public static final String NAME = "ProgramLocationChange";

    private ProgramLocation loc;
    private WeakReference<Program> programRef;
    /**
     * Construct a new ProgramLocationEvent.
     * @param src the name of the plugin that generated this event.
     * @param loc the ProgramLocation object that contains the new location.
     * @param program the Program for which the loc object refers.
     */
    public ProgramLocationPluginEvent(String src, ProgramLocation loc, Program program) {
        super(src,NAME);
        // don't allow a null for a program location
        if (loc == null) {
        	NullPointerException exc = new NullPointerException(
					"Null ProgramLocation passed to create a Plugin event");
        	Msg.showError(this, 
					null, "Error", "Null ProgramLocationEvent being created.  Trace and remove this problem", exc);
        }
        this.loc = loc;
        this.programRef = new WeakReference<Program>(program);
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

    @Override
    protected String getDetails() {
		if (loc != null) {
			return loc.getClass().getName() + " addr==> " + loc.getAddress() +"\n";
		}			            	
		return super.getDetails();
    }
}
