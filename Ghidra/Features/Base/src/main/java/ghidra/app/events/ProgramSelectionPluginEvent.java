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
import ghidra.program.util.ProgramSelection;

/**
 * Plugin event generated when the selection in a program changes.
 */
public final class ProgramSelectionPluginEvent extends AbstractSelectionPluginEvent {

	/**
	 * The name of this plugin event.
	 */
	public static final String NAME = "ProgramSelection";

	/**
	 * Construct a new plugin event
	 * 
	 * @param src the name of the plugin that generated this event
	 * @param sel the program selection
	 * @param program the program associated with this event
	 */
	public ProgramSelectionPluginEvent(String src, ProgramSelection sel,
			Program program) {
		super(src, NAME, sel, program);
	}
}
