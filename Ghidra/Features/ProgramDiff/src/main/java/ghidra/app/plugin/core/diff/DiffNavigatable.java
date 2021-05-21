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
package ghidra.app.plugin.core.diff;

import javax.swing.Icon;

import ghidra.app.nav.*;
import ghidra.app.plugin.core.codebrowser.CodeViewerLocationMemento;
import ghidra.app.util.HighlightProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * This is a navigatable for use by the right-hand listing of the Diff.
 * It should navigate within the Diff's listing, which would then reposition 
 * the CodeViewer's listing.
 */
class DiffNavigatable implements Navigatable {

	private ProgramDiffPlugin diffPlugin;
	private Navigatable navigatable;
	private boolean disposed = false;
	private WeakSet<NavigatableRemovalListener> navigationListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	/**
	 * The navigatable for the Diff. The CodeViewerService provides Diff with a listing,
	 * so where appropriate this navigatable will defer to the CodeViewerService navigatable.
	 * @param diffPlugin the plugin for the Diff which can be used to obtain needed info.
	 * @param navigatable navigatable that the CodeViewerService provides.
	 */
	DiffNavigatable(ProgramDiffPlugin diffPlugin, Navigatable navigatable) {
		this.diffPlugin = diffPlugin;
		this.navigatable = navigatable;
	}

	@Override
	public boolean goTo(Program program, ProgramLocation location) {
		// Defer to the CodeViewer navigatable.
		return navigatable.goTo(program, location);
	}

	@Override
	public ProgramLocation getLocation() {
		// CodeViewer is designed to handle this based on focus.
		return navigatable.getLocation();
	}

	@Override
	public Program getProgram() {
		return diffPlugin.getSecondProgram();
	}

	@Override
	public LocationMemento getMemento() {
		int cursorOffset = diffPlugin.getListingPanel().getFieldPanel().getCursorOffset();
		return new CodeViewerLocationMemento(diffPlugin.getSecondProgram(),
			diffPlugin.getCurrentLocation(), cursorOffset);
	}

	@Override
	public void setMemento(LocationMemento memento) {
		CodeViewerLocationMemento cvMemento = (CodeViewerLocationMemento) memento;
		int cursorOffset = cvMemento.getCursorOffset();
		diffPlugin.getListingPanel().getFieldPanel().positionCursor(cursorOffset);

	}

	@Override
	public Icon getNavigatableIcon() {
		// Just use the CodeViewer's navigatable icon.
		return navigatable.getNavigatableIcon();
	}

	@Override
	public boolean isConnected() {
		return true;
	}

	@Override
	public boolean supportsMarkers() {
		return isConnected();
	}

	@Override
	public void requestFocus() {
		diffPlugin.getListingPanel().getFieldPanel().requestFocus();
	}

	@Override
	public boolean isVisible() {
		// Is the CodeViewer visible and the Diff visible?
		return navigatable.isVisible() && diffPlugin.isShowingDiff();
	}

	@Override
	public long getInstanceID() {
		// CodeViewer provides the listing for Diff.
		return navigatable.getInstanceID();
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		if (selection == null) {
			selection = new ProgramSelection();
		}
		diffPlugin.setProgram2Selection(selection);
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		// The right-hand Diff listing doesn't currently support highlight.
	}

	@Override
	public ProgramSelection getSelection() {
		// CodeViewer is designed to handle this based on focus.
		return navigatable.getSelection();
	}

	@Override
	public ProgramSelection getHighlight() {
		// CodeViewer is designed to handle this based on focus.
		return navigatable.getHighlight();
	}

	@Override
	public String getTextSelection() {
		return navigatable.getTextSelection();
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.add(listener);
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.remove(listener);
	}

	public void dispose() {
		disposed = true;
		for (NavigatableRemovalListener listener : navigationListeners) {
			listener.navigatableRemoved(this);
		}
	}

	@Override
	public boolean isDisposed() {
		return disposed;
	}

	@Override
	public boolean supportsHighlight() {
		return true;
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// CodeViewerProvider handles the other listing (the Diff listing) highlights.
		navigatable.setHighlightProvider(highlightProvider, program);
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// CodeViewerProvider handles the other listing (the Diff listing) highlights.
		navigatable.removeHighlightProvider(highlightProvider, program);
	}
}
