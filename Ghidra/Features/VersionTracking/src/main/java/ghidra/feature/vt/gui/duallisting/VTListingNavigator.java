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
package ghidra.feature.vt.gui.duallisting;

import javax.swing.Icon;

import ghidra.app.nav.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.features.base.codecompare.listing.ListingCodeComparisonPanel;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.UniversalIdGenerator;

public class VTListingNavigator implements Navigatable {

	private final ListingCodeComparisonPanel dualListingPanel;
	private final ListingPanel listingPanel;
	private long id;

	public VTListingNavigator(ListingCodeComparisonPanel dualListingPanel,
			ListingPanel listingPanel) {

		this.dualListingPanel = dualListingPanel;
		this.listingPanel = listingPanel;
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
		return listingPanel.goTo(location);
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
		// unsupported
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
