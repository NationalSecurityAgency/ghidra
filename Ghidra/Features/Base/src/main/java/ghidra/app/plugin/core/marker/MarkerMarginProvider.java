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
package ghidra.app.plugin.core.marker;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.services.MarkerService;
import ghidra.app.services.MarkerSet;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MarkerLocation;

/**
 * The provider which renders the marker margin, usually placed to the left of listing
 * {@link FieldPanel}s.
 * 
 * <p>
 * These are managed by a {@link MarkerManager}. Obtain one via
 * {@link MarkerService#createMarginProvider()}.
 */
public class MarkerMarginProvider implements MarginProvider {
	private final MarkerManager markerManager;
	private final MarkerPanel markerPanel;

	private Program program;
	private VerticalPixelAddressMap pixmap;

	MarkerMarginProvider(MarkerManager markerManager) {
		this.markerManager = markerManager;
		this.markerPanel = new MarkerPanel(markerManager);

		this.markerPanel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				MarkerClickedListener markerClickedListener =
					markerManager.getMarkerClickedListener();
				if (e.getClickCount() != 2 || markerClickedListener == null) {
					return;
				}
				MarkerLocation location = getMarkerLocation(e.getX(), e.getY());
				markerClickedListener.markerDoubleClicked(location);
			}
		});
	}

	void repaintPanel() {
		markerPanel.repaint();
	}

	@Override
	public JComponent getComponent() {
		return markerPanel;
	}

	private Address getAddress(int y) {
		if (pixmap == null) {
			return null;
		}
		int i = pixmap.findLayoutAt(y);
		return pixmap.getLayoutAddress(i);
	}

	@Override
	public MarkerLocation getMarkerLocation(int x, int y) {
		Address addr = getAddress(y);
		if (addr == null) {
			return null;
		}
		MarkerSet marker = markerManager.getMarkerSet(program, addr);
		return new MarkerLocation(marker, program, addr, x, y);
	}

	@Override
	public boolean isResizeable() {
		return false;
	}

	@Override
	public void setProgram(Program program, AddressIndexMap addrMap,
			VerticalPixelAddressMap pixmap) {
		this.program = program;
		this.pixmap = pixmap;

		this.markerPanel.setProgram(program, addrMap, pixmap);

		markerManager.updateMarkerSets(program, true, false, true);
	}

	/*testing*/ String generateToolTip(MouseEvent event) {
		return markerPanel.generateToolTip(event);
	}

}
