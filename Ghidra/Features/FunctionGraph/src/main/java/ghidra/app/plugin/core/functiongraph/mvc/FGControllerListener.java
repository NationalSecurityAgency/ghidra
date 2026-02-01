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
package ghidra.app.plugin.core.functiongraph.mvc;

import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public interface FGControllerListener {

	/**
	 * Called when the {@link FGData} for the current viewer has been set on the controller.
	 */
	public void dataChanged();

	/**
	 * A notification for when the user has changed the location by interacting with the Function 
	 * Graph UI.  
	 * @param location the new location
	 * @param vertexChanged true if a new vertex has been selected
	 */
	public void userChangedLocation(ProgramLocation location, boolean vertexChanged);

	/**
	 * A notification for when the user has changed the selection by interacting with the Function 
	 * Graph UI.  
	 * @param selection the new selection
	 */
	public void userChangedSelection(ProgramSelection selection);

	/**
	 * A notification for when the user has selected text in a vertex by interacting with the 
	 * Function Graph UI.  
	 * @param s the selected text
	 */
	public void userSelectedText(String s);

	/**
	 * Called when the users requests the tool to navigate to a new location, such as when 
	 * double-clicking an xref.
	 * @param location the location
	 */
	public void userNavigated(ProgramLocation location);
}
