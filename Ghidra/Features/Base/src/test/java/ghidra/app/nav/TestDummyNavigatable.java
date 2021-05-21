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
package ghidra.app.nav;

import javax.swing.Icon;

import ghidra.app.util.HighlightProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * A stub of the {@link Navigatable} interface.  This can be used to supply a test navigatable 
 * or to spy on system internals by overriding methods as needed.
 */
public class TestDummyNavigatable implements Navigatable {

	@Override
	public long getInstanceID() {
		// stub
		return 0;
	}

	@Override
	public boolean goTo(Program program, ProgramLocation location) {
		// stub
		return false;
	}

	@Override
	public ProgramLocation getLocation() {
		// stub
		return null;
	}

	@Override
	public Program getProgram() {
		// stub
		return null;
	}

	@Override
	public LocationMemento getMemento() {
		// stub
		return null;
	}

	@Override
	public void setMemento(LocationMemento memento) {
		// stub
	}

	@Override
	public Icon getNavigatableIcon() {
		// stub
		return null;
	}

	@Override
	public boolean isConnected() {
		// stub
		return false;
	}

	@Override
	public boolean supportsMarkers() {
		// stub
		return false;
	}

	@Override
	public void requestFocus() {
		// stub
	}

	@Override
	public boolean isVisible() {
		// stub
		return false;
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		// stub
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		// stub
	}

	@Override
	public ProgramSelection getSelection() {
		// stub
		return null;
	}

	@Override
	public ProgramSelection getHighlight() {
		// stub
		return null;
	}

	@Override
	public String getTextSelection() {
		// stub
		return null;
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		// stub
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		// stub
	}

	@Override
	public boolean isDisposed() {
		// stub
		return false;
	}

	@Override
	public boolean supportsHighlight() {
		// stub
		return false;
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// stub
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// stub
	}
}
