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
import java.awt.image.ImageObserver;
import java.util.Iterator;
import java.util.List;

import javax.swing.ImageIcon;

import ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MarkerLocation;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;
import resources.ResourceManager;

class PointMarkerSet extends MarkerSetImpl {

	private Image image;
	private ImageObserver imageObserver;
	private Color fillColor;

	/**
	 * @param navigationManager  manager for these point markers
	 * @param name the name for this point marker
	 * @param desc the description associated with this point marker
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground colorBackground the color of marked areas in navigation bar
	 *              If color is null, no results are displayed in the associated marker bar.
	 * @param markerColor the color of the marker
	 * @param icon the icon used to represent the cursor in the marker margin
	 * @param isPreferred true indicates higher priority than all non-preferred MarkerSets
	 * @param program the program to which the markers apply
	 */
	PointMarkerSet(MarkerManager navigationManager, String name, String desc, int priority,
			boolean showMarkers, boolean showNavigation, boolean colorBackground, Color markerColor,
			ImageIcon icon, boolean isPreferred, Program program) {
		super(navigationManager, program, name, desc, priority, showMarkers, showNavigation,
			colorBackground,
			markerColor, isPreferred);
		if (icon == null) {
			icon = ResourceManager.loadImage("images/warning.png");
		}
		icon = ResourceManager.getScaledIcon(icon, 16, 16, Image.SCALE_SMOOTH);
		image = icon.getImage();
		imageObserver = icon.getImageObserver();
		if (markerColor != null) {
			fillColor = getFillColor(markerColor);
		}
	}

	/**
	 * @param navigationManager  manager for these point markers
	 * @param name the name for this point marker
	 * @param desc the description associated with this point marker
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground colorBackground the color of marked areas in navigation bar
	 *              If color is null, no results are displayed in the associated marker bar.
	 * @param markerColor the color of the marker
	 * @param icon the icon used to represent the cursor in the marker margin
	 * @param program the program to which the markers apply
	 */
	PointMarkerSet(MarkerManager navigationManager, String name, String desc, int priority,
			boolean showMarkers, boolean showNavigation, boolean colorBackground, Color markerColor,
			ImageIcon icon, Program program) {
		this(navigationManager, name, desc, priority, showMarkers, showNavigation,
			colorBackground,
			markerColor, icon, true, program);
	}

	@Override
	protected void doPaintMarkers(Graphics g, VerticalPixelAddressMap pixmap, int index,
			AddressIndexMap map, List<Integer> layouts) {

		if (layouts == null) {
			return;
		}

		Iterator<Integer> it = layouts.iterator();
		while (it.hasNext()) {
			int i = it.next().intValue();
			int yStart = pixmap.getMarkPosition(i);

			Image curImage = getMarkerImage(pixmap, i, yStart);

			g.drawImage(curImage, 0, yStart, imageObserver);
		}
	}

	private Image getMarkerImage(VerticalPixelAddressMap pixmap, int i, int yStart) {
		if (markerDescriptor == null) {
			return image;
		}

		Address address = pixmap.getLayoutAddress(i);
		Program program = mgr.getProgram();
		MarkerLocation loc = new MarkerLocation(this, program, address, 0, yStart);
		ImageIcon icon = markerDescriptor.getIcon(loc);
		if (icon != null) {
			return icon.getImage();
		}

		return image;
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
			if ((endY - startY) % 2 != 0) {
				endY--;
			}
			for (int y = endY; y >= startY; y -= 2) {
				int paintY = Math.min(height - MARKER_HEIGHT, y);
				g.setColor(fillColor);
				g.fillRect(0, paintY, width - MARKER_WIDTH_OFFSET, MARKER_HEIGHT);
				g.setColor(markerColor);
				g.drawRect(0, paintY, width - MARKER_WIDTH_OFFSET, MARKER_HEIGHT);
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.codebrowser.MarkerSetImpl#getNavIcon()
	 */
	@Override
	public ImageIcon getNavIcon() {

		BufferedImage bufferedImage = new BufferedImage(14, 14, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = bufferedImage.createGraphics();

		int height = MarkerSetImpl.MARKER_HEIGHT;
		int width = 2 * height;
		int x = (14 - width) / 2;
		int y = (14 - height) / 2;

		g.setColor(markerColor);
		g.fillRect(x - 1, y - 1, width + 2, height + 2);
		g.setColor(fillColor);
		g.fillRect(x, y, width, height);

		return ResourceManager.getImageIconFromImage("Point Marker Set Nav Icon", bufferedImage);
	}

}
