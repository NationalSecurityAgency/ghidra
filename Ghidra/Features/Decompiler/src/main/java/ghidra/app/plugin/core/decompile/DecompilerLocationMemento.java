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
package ghidra.app.plugin.core.decompile;

import ghidra.app.nav.LocationMemento;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import docking.widgets.fieldpanel.support.ViewerPosition;

public class DecompilerLocationMemento extends LocationMemento {

	private final ViewerPosition viewerPosition;
	
	public DecompilerLocationMemento(Program program, ProgramLocation location,
			ViewerPosition viewerPosition) {
		super(program, location);
		this.viewerPosition = viewerPosition;
	}
	public DecompilerLocationMemento(SaveState saveState, Program[] programs) {
		super(saveState, programs);
		int index = saveState.getInt("INDEX", 0);
		int xOffset = saveState.getInt("X_OFFSET", 0);
		int yOffset = saveState.getInt("Y_OFFSET", 0);
		viewerPosition = new ViewerPosition(index, xOffset, yOffset);
	}

	public ViewerPosition getViewerPosition() {
		return viewerPosition;
	}
	
	@Override
	public void saveState(SaveState saveState) {
		super.saveState( saveState );
		saveState.putInt("INDEX", viewerPosition.getIndexAsInt());
		saveState.putInt("X_OFFSET", viewerPosition.getXOffset());
		saveState.putInt("Y_OFFSET", viewerPosition.getYOffset());
	}
}
