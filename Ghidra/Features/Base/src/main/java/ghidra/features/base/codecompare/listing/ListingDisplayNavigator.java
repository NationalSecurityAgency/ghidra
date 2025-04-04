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
package ghidra.features.base.codecompare.listing;

import javax.swing.Icon;

import ghidra.app.nav.*;
import ghidra.app.services.GoToService;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.UniversalIdGenerator;

/**
 * Navigator for the listings contained in a ListingCodeComparisonPanel.
 */
class ListingDisplayNavigator implements Navigatable {

	private final ListingPanel listingPanel;
	private long id;
	private GoToService goToService;

	/**
	 * Constructor for a dual listing navigator.
	 * 
	 * @param listingPanel the dual listing whose left or right listing panel is to be controlled.
	 * @param goToService which side LEFT or RIGHT. false means it's for the right side listing.
	 */
	ListingDisplayNavigator(ListingPanel listingPanel, GoToService goToService) {

		this.listingPanel = listingPanel;
		this.goToService = goToService;
		id = UniversalIdGenerator.nextID().getValue();
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		// not used
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		// not used
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
	public void removeHighlightProvider(ListingHighlightProvider highlightProvider,
			Program program) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(ListingHighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}
}
