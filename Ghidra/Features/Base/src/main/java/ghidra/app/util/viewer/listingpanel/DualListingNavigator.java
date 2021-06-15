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
package ghidra.app.util.viewer.listingpanel;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import ghidra.app.nav.*;
import ghidra.app.services.GoToService;
import ghidra.app.util.HighlightProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.UniversalIdGenerator;

/**
 * Navigator for the listings contained in a ListingCodeComparisonPanel.
 */
class DualListingNavigator implements Navigatable {

	private final ListingPanel listingPanel;
	private List<NavigatableRemovalListener> listeners =
		new ArrayList<>();
	private long id;
	private GoToService goToService;

	/**
	 * Constructor for a dual listing navigator.
	 * @param dualListingPanel the dual listing whose left or right listing panel is to be controlled.
	 * @param isLeftSide true indicates that this navigator is for the left side listing.
	 * false means it's for the right side listing.
	 */
	DualListingNavigator(ListingCodeComparisonPanel dualListingPanel, boolean isLeftSide) {

		this.listingPanel =
			isLeftSide ? dualListingPanel.getLeftPanel() : dualListingPanel.getRightPanel();
		this.goToService = dualListingPanel.getGoToService(isLeftSide);
		id = UniversalIdGenerator.nextID().getValue();
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		listeners.add(listener);
	}

	@Override
	public ProgramSelection getSelection() {
		return listingPanel.getProgramSelection();
	}

	@Override
	public ProgramSelection getHighlight() {
		return listingPanel.getProgramHighlight();
	}

	@Override
	public String getTextSelection() {
		return listingPanel.getTextSelection();
	}

	@Override
	public long getInstanceID() {
		return id;
	}

	@Override
	public ProgramLocation getLocation() {
		return listingPanel.getProgramLocation();
	}

	@Override
	public LocationMemento getMemento() {
		return new LocationMemento(getProgram(), getLocation());
	}

	@Override
	public Icon getNavigatableIcon() {
		return null;
	}

	@Override
	public Program getProgram() {
		return listingPanel.getProgram();
	}

	@Override
	public boolean goTo(Program program, ProgramLocation location) {
		if (program != listingPanel.getProgram()) {
			return false;
		}
		return goToService.goTo(location, program);
	}

	@Override
	public boolean isConnected() {
		return false;
	}

	@Override
	public boolean supportsMarkers() {
		return false;
	}

	@Override
	public boolean isDisposed() {
		return false;
	}

	@Override
	public boolean isVisible() {
		return true;
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void requestFocus() {
		listingPanel.requestFocus();
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		listingPanel.setHighlight(highlight);
	}

	@Override
	public void setMemento(LocationMemento memento) {
		// currently unsupported
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		listingPanel.setSelection(selection);
	}

	@Override
	public boolean supportsHighlight() {
		return false;
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}
}
