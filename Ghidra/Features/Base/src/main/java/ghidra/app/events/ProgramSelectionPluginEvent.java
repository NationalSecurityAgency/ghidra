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
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

import java.lang.ref.WeakReference;

/**
 *  Plugin event generated when the selection in a program changes.
 */
public final class ProgramSelectionPluginEvent extends PluginEvent {
	
	/**
	 * The name of this plugin event.
	 */
    public static final String NAME = "ProgramSelection";

    private ProgramSelection selection;
    private WeakReference<Program> programRef;

	/**
	 * Construct a new plugin event
	 * @param src the name of the plugin that generated this event
	 * @param sel the program selection
	 * @param program the program associated with this event
	 */
    public ProgramSelectionPluginEvent(String src,ProgramSelection sel,
            Program program) {
        super(src,NAME);
        
        // don't allow null program selection
        if (sel == null) {
        	NullPointerException exc = new NullPointerException(
				"Null ProgramSelection in creating Selection Plugin Event");
        	Msg.showError(this, 
				null, "Internal Error", "Null ProgramSelectionEvent being created.  Trace and remove this problem", exc);
        }
        
        this.selection = sel;
        this.programRef = new WeakReference<Program>(program);
    }

	/**
	 * Returns the program selection contained in this event.
	 * @return ProgramSelection the program selection in this event.
	 */
    public ProgramSelection getSelection() {
        return selection;
    }

    /**
     * Returns the Program object that the selection refers to. 
     */
    public Program getProgram() {
        return programRef.get();
    }
    
    @Override
    protected String getDetails() {
		return "Address Set ==> " + selection;
    }
}
