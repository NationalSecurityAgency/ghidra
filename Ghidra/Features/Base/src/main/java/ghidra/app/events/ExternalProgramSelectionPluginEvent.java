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
import ghidra.program.util.ProgramSelection;

/**
 * Plugin event generated when a tool receives an
 * ProgramSelectionToolEvent; the selection in the external tool has
 * changed.
 */
@ToolEventName(ExternalProgramSelectionPluginEvent.TOOL_EVENT_NAME) // this allows the event to be considered for tool connection
public final class ExternalProgramSelectionPluginEvent extends PluginEvent {
	/**
	 * The name of this plugin event.
	 */
	public static final String NAME = "ExternalProgramSelection";
	public static final String TOOL_EVENT_NAME = "Program Selection";

	private ProgramSelection selection;
	private WeakReference<Program> programRef;

	/**
	 * Construct a new event.
	 * @param src source of this event
	 * @param sel selection
	 * @param program program that is open
	 */
	public ExternalProgramSelectionPluginEvent(String src, ProgramSelection sel, Program program) {
		super(src, NAME);
		this.selection = sel;
		this.programRef = new WeakReference<>(program);
	}

	/**
	 * Get the selection for this event.
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

}
