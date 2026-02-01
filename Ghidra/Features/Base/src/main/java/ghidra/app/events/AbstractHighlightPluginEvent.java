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

/**
 * Plugin event generated when the highlight in a program changes.
 */
public abstract class AbstractHighlightPluginEvent extends PluginEvent {

	private final ProgramSelection highlight;
	private final WeakReference<Program> programRef;

	/**
	 * Construct a new event.
	 * 
	 * @param sourceName the name of the plugin that generated this event
	 * @param eventName the name of the event type
	 * @param highlight the program highlight
	 * @param program the program associated with this event
	 */
	public AbstractHighlightPluginEvent(String sourceName, String eventName,
			ProgramSelection highlight, Program program) {
		super(sourceName, eventName);
		this.highlight = highlight;
		this.programRef = new WeakReference<Program>(program);
	}

	/**
	 * Get the program highlight contained in this event.
	 * 
	 * @return the program highlight in this event.
	 */
	public ProgramSelection getHighlight() {
		return highlight;
	}

	/**
	 * Get the program that the highlight refers to.
	 * 
	 * @return the program
	 */
	public Program getProgram() {
		return programRef.get();
	}

	@Override
	protected String getDetails() {
		return getClass() + " ==> " + highlight;
	}
}
