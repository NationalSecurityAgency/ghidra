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

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.Iterator;
import java.util.List;

import javax.swing.ImageIcon;

import ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;
import resources.ResourceManager;

class AreaMarkerSet extends MarkerSetImpl {

	/**
	 * @param markerManager manager for these area markers
	 * @param name the name for this area marker
	 * @param desc the description associated with this area marker
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground the color of marked areas in navigation bar
	 *              If color is null, no results are displayed in the associated marker bar.
	 * @param markerColor the color for the marker
	 * @param isPreferred true indicates higher priority than all non-preferred MarkerSets
	 * @param program the program to which the markers apply
	 */
	AreaMarkerSet(MarkerManager markerManager, String name, String desc, int priority,
			boolean showMarkers, boolean showNavigation, boolean colorBackground, Color markerColor,
			boolean isPreferred, Program program) {
		super(markerManager, program, name, desc, priority, showMarkers, showNavigation,
			colorBackground,
			markerColor, isPreferred);
	}

	/**
	 * @param markerManager manager for these area markers
	 * @param name the name for this area marker
	 * @param desc the description associated with this area marker
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground the color of marked areas in navigation bar
	 *              If color is null, no results are displayed in the associated marker bar.
	 * @param markerColor the color for the marker
	 * @param program the program to which the markers apply
	 */
	AreaMarkerSet(MarkerManager markerManager, String name, String desc, int priority,
			boolean showMarkers, boolean showNavigation, boolean colorBackground, Color markerColor,
			Program program) {
		this(markerManager, name, desc, priority, showMarkers, showNavigation,
			colorBackground, markerColor, false, program);
	}

	@Override
	protected void doPaintMarkers(Graphics g, VerticalPixelAddressMap pixmap, int index,
			AddressIndexMap map, List<Integer> layouts) {
		if (layouts == null) {
			return;
		}

		Iterator<Integer> it = layouts.iterator();
		g.setColor(markerColor);
		while (it.hasNext()) {
			int i = it.next().intValue();
			int yStart = pixmap.getBeginPosition(i);
			int yEnd = pixmap.getEndPosition(i);
			g.fillRect(7, yStart, 3, yEnd - yStart + 1);
		}
	}

	@Override
	protected void doPaintNavigation(Graphics g, int height, int width, SortedRangeList rangeList) {

		if (rangeList == null) {
			return;
		}

		g.setColor(markerColor);
		for (Range range : rangeList) {
			int startY = range.min;
			int endY = range.max;
			int len = endY - startY;
			if (len < MARKER_HEIGHT) {
				len = MARKER_HEIGHT;
			}

			g.fillRect(MARKER_WIDTH_OFFSET, startY, width - MARKER_WIDTH_OFFSET, len);
		}
	}

	@Override
	public ImageIcon getNavIcon() {

		BufferedImage image = new BufferedImage(14, 14, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = image.createGraphics();

		int height = MarkerSetImpl.MARKER_HEIGHT;
		int width = 2 * height;
		int x = (14 - width) / 2;
		int y = (14 - height) / 2;

		g.setColor(markerColor);
		g.fillRect(x - 1, y - 1, width + 2, height + 2);

		return ResourceManager.getImageIconFromImage("Area Marker Set Nav Icon", image);
	}

}
