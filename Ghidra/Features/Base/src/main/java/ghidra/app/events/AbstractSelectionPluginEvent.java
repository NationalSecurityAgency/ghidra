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
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

/**
 * Plugin event generated when the selection in a program changes.
 */
public abstract class AbstractSelectionPluginEvent extends PluginEvent {

	private final ProgramSelection selection;
	private final WeakReference<Program> programRef;

	/**
	 * Construct a new plugin event
	 * 
	 * @param sourceName the name of the plugin that generated this event
	 * @param eventName the name of the event type
	 * @param selection the program selection
	 * @param program the program associated with this event
	 */
	public AbstractSelectionPluginEvent(String sourceName, String eventName,
			ProgramSelection selection, Program program) {
		super(sourceName, eventName);

		// don't allow null program selection
		if (selection == null) {
			NullPointerException exc = new NullPointerException(
				"Null ProgramSelection in creating Selection Plugin Event");
			Msg.showError(this,
				null, "Internal Error",
				"Null SelectionEvent being created.  Trace and remove this problem", exc);
		}

		this.selection = selection;
		this.programRef = new WeakReference<Program>(program);
	}

	/**
	 * Get the program selection contained in this event.
	 * 
	 * @return the program selection in this event.
	 */
	public ProgramSelection getSelection() {
		return selection;
	}

	/**
	 * Get the program that the selection refers to.
	 * 
	 * @return the program
	 */
	public Program getProgram() {
		return programRef.get();
	}

	@Override
	protected String getDetails() {
		return getClass() + " ==> " + selection;
	}
}
