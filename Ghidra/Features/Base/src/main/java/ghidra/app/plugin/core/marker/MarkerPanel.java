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

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.ToolTipManager;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Panel to display markers. Normally placed to the left hand side of the scrolled
 * {@link FieldPanel}.
 */
public class MarkerPanel extends JPanel {

	private MarkerManager manager;

	private Program program;
	private AddressIndexMap addrMap;
	private VerticalPixelAddressMap pixmap;

	MarkerPanel(MarkerManager manager) {
		super();
		this.manager = manager;

		this.setPreferredSize(new Dimension(16, 1));
		ToolTipManager.sharedInstance().registerComponent(this);
	}

	void setProgram(Program program, AddressIndexMap addrMap, VerticalPixelAddressMap pixmap) {
		this.program = program;
		this.addrMap = addrMap;
		this.pixmap = pixmap;
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		manager.paintMarkers(program, g, pixmap, addrMap);
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		String tip = generateToolTip(event);
		manager.showToolTipPopup(event, tip);
		return null; // signal not to show a Java tooltip
	}

	private static String toHTML(List<String> lines) {
		if (lines.isEmpty()) {
			return null;
		}

		StringBuilder buffy = new StringBuilder("<html><font size=\"" + 4 + "\">");
		for (String string : lines) {
			buffy.append(string).append("<BR>");
		}
		return buffy.toString();
	}

	String generateToolTip(MouseEvent event) {
		if (pixmap == null) {
			return null;
		}

		int y = event.getY();
		int x = event.getX();
		int layoutIndex = pixmap.findLayoutAt(y);
		Address layoutAddress = pixmap.getLayoutAddress(layoutIndex);
		if (layoutAddress == null) {
			return null;
		}

		List<String> lines = getMarkerTooltipLines(y, x, layoutIndex, layoutAddress);
		return toHTML(lines);
	}

	private List<String> getMarkerTooltipLines(int y, int x, int layoutIndex,
			Address layoutAddress) {
		Address endAddr = pixmap.getLayoutEndAddress(layoutIndex);
		return manager.getMarkerTooltipLines(program, y, layoutIndex, layoutAddress, endAddr);
	}
}
