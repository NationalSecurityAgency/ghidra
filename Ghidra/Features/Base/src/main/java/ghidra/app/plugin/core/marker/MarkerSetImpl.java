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

import java.awt.Color;
import java.awt.Graphics;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import generic.json.Json;
import ghidra.app.services.MarkerDescriptor;
import ghidra.app.services.MarkerSet;
import ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Swing;
import ghidra.util.datastruct.SortedRangeList;

abstract class MarkerSetImpl implements MarkerSet {

	protected MarkerManager mgr;
	private Program program;

	private String name;
	protected String description;
	protected int priority = 0;
	protected boolean active = true;

	protected AddressSetCollection markers;
	protected SortedRangeList overview = null;
	protected List<Integer> activeLayouts = null;

	protected Color markerColor;

	protected int lastHeight = 1;
	protected int lastWidth = 16;

	protected MarkerDescriptor markerDescriptor;

	protected final static int MARKER_WIDTH_OFFSET = 7;
	protected final static int MARKER_HEIGHT = 4;

	private static final int COLOR_VALUE = 200;

	private boolean showMarkers;
	private boolean showNavigation;
	private boolean colorBackground;
	private boolean isPreferred;

	MarkerSetImpl(MarkerManager mgr, Program program, String name, String desc, int priority,
			boolean showMarkers,
			boolean showNavigation, boolean colorBackground, Color markerColor,
			boolean isPreferred) {

		this.mgr = mgr;
		this.program = program;
		this.name = name;
		this.description = desc;
		this.priority = priority;
		this.showMarkers = showMarkers;
		this.showNavigation = showNavigation;
		this.colorBackground = colorBackground;
		this.markerColor = markerColor;
		this.isPreferred = isPreferred;
		if (markerColor == null) {
			throw new NullPointerException("Marker color can't be null");
		}
		markers = new ModifiableAddressSetCollection();
	}

	protected abstract void doPaintMarkers(Graphics g, VerticalPixelAddressMap pixmap, int index,
			AddressIndexMap map, List<Integer> layouts);

	protected abstract void doPaintNavigation(Graphics g, int height, int width,
			SortedRangeList rangeList);

	/**
	 * Returns the Navigator Icon for this marker set
	 * @return the Navigator Icon for this marker set
	 */
	public abstract ImageIcon getNavIcon();

	@Override
	public void setMarkerDescriptor(MarkerDescriptor markerDescriptor) {
		this.markerDescriptor = markerDescriptor;
	}

	@Override
	public Color getMarkerColor() {
		return markerColor;
	}

	@Override
	public void setMarkerColor(Color markerColor) {
		this.markerColor = markerColor;
		mgr.markersChanged(program);
	}

	public String getDescription() {
		return description;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getPriority() {
		return priority;
	}

	@Override
	public boolean isPreferred() {
		return isPreferred;
	}

	@Override
	public void setAddressSetCollection(AddressSetCollection set) {

		//
		// Note: this method allows clients to provide an implementation of AddressSetCollection
		//       that could be mutated off the Swing thread.   This is not thread safe.   At the
		//       time of this writing, the only client of this method was coded to either be
		//       immutable or to mutate data synchronously.  There will always be the potential
		//       for clients to misuse this method.  Don't do that.
		//

		if (set == null) {
			set = new ModifiableAddressSetCollection();
		}

		markers = set;
		clearAndUpdate();
	}

	@Override
	public void setAddressSet(AddressSetView set) {
		markers = new ModifiableAddressSetCollection();
		if (set != null) {
			add(set);
		}
	}

	@Override
	public void add(Address addr) {
		add(addr, addr);
	}

	@Override
	public void add(AddressRange range) {
		add(range.getMinAddress(), range.getMaxAddress());
	}

	@Override
	public void add(Address start, Address end) {
		checkModifiable();
		((ModifiableAddressSetCollection) markers).addRange(start, end);
		clearAndUpdate();
	}

	@Override
	public void add(AddressSetView addrSet) {
		checkModifiable();
		((ModifiableAddressSetCollection) markers).add(addrSet);
		clearAndUpdate();
	}

	@Override
	public void clear(Address start, Address end) {
		checkModifiable();
		((ModifiableAddressSetCollection) markers).deleteRange(start, end);
		clearAndUpdate();
	}

	private void checkModifiable() {
		if (!(markers instanceof ModifiableAddressSetCollection)) {
			throw new IllegalStateException("Attempted to modify a read-only marker set.");
		}
	}

	@Override
	public void clear(AddressRange range) {
		clear(range.getMinAddress(), range.getMaxAddress());
	}

	@Override
	public void clear(Address address) {
		clear(address, address);
	}

	@Override
	public void clear(AddressSetView addrSet) {
		checkModifiable();
		((ModifiableAddressSetCollection) markers).delete(addrSet);
		clearAndUpdate();
	}

	@Override
	public void clearAll() {
		markers = new ModifiableAddressSetCollection();
		clearAndUpdate();
	}

	private void clearAndUpdate() {
		assertSwing();
		overview = null;
		activeLayouts = null;
		mgr.markersChanged(program);
	}

	void updateView(boolean updateMarkers, boolean updateNavigation) {
		if (updateMarkers) {
			activeLayouts = null;
		}
		if (updateNavigation) {
			overview = null;
		}
	}

	public final void paintMarkers(Graphics g, int index, VerticalPixelAddressMap pixmap,
			AddressIndexMap map) {
		if (showMarkers) {
			List<Integer> layouts = computeActiveLayouts(pixmap, map);
			doPaintMarkers(g, pixmap, index, map, layouts);
		}
	}

	public final void paintNavigation(Graphics g, int height, NavigationPanel panel,
			AddressIndexMap map) {
		if (showNavigation) {
			SortedRangeList newOverview = computeNavigationIndexes(height, map);
			doPaintNavigation(g, height, panel.getWidth(), newOverview);
		}
	}

	protected static Color getFillColor(Color c) {
		int red = (c.getRed() + 3 * COLOR_VALUE) / 4;
		int green = (c.getGreen() + 3 * COLOR_VALUE) / 4;
		int blue = (c.getBlue() + 3 * COLOR_VALUE) / 4;
		return new Color(red, green, blue);
	}

	@Override
	public int compareTo(MarkerSet other) {
		int result = 1;
		if (other != null) {
			if (this.isPreferred() == other.isPreferred()) {
				result = priority - other.getPriority();
			}	//otherwise, exactly one isPreferred
			else if (this.isPreferred()) {
				result = 1;
			}
			else {
				result = -1;
			}
		}
		return result;
	}

	@Override
	public boolean contains(Address addr) {
		assertSwing();
		return markers.contains(addr);
	}

	private List<Integer> computeActiveLayouts(VerticalPixelAddressMap pixmap,
			AddressIndexMap map) {

		if (pixmap == null) {
			return null;
		}

		if (activeLayouts != null) {
			return activeLayouts; // use cache
		}

		List<Integer> newLayouts = new ArrayList<>();
		int n = pixmap.getNumLayouts();
		for (int i = 0; i < n; i++) {
			Address addr = pixmap.getLayoutAddress(i);
			if (addr == null) {
				continue;
			}

			Address end = pixmap.getLayoutEndAddress(i);
			if (markers.intersects(addr, end)) {
				newLayouts.add(i);
			}
		}

		activeLayouts = newLayouts;
		return newLayouts;
	}

	private SortedRangeList computeNavigationIndexes(int height, AddressIndexMap map) {

		lastHeight = height;
		double numIndexes = map.getIndexCount().doubleValue();
		if (markers.isEmpty() || height == 0 || numIndexes == 0) {
			return null;
		}

		if (overview != null) {
			return overview; // use cache
		}

		SortedRangeList newOverview = new SortedRangeList();
		double indexSize = numIndexes / height;
		if (numIndexes < height && (this instanceof PointMarkerSet)) {
			int nIndexes = map.getIndexCount().intValue();
			for (int i = 0; i < nIndexes; i++) {
				Address addr = map.getAddress(BigInteger.valueOf(i));
				if ((addr != null) && markers.contains(addr)) {
					int index = (int) (i / indexSize);
					newOverview.addRange(index, index);
				}
			}
		}
		else if (markers.hasFewerRangesThan(height)) {
			FieldSelection sel = map.getFieldSelection(markers.getCombinedAddressSet());
			int n = sel.getNumRanges();
			for (int i = 0; i < n; i++) {
				FieldRange range = sel.getFieldRange(i);
				int start = (int) (range.getStart().getIndex().doubleValue() / indexSize);
				int end = (int) (range.getEnd().getIndex().doubleValue() / indexSize);
				newOverview.addRange(start, end);
			}

		}
		else {
			BigInteger startIndex = BigInteger.ZERO;
			for (int i = 0; i < height; i++) {
				BigInteger endIndex = BigDecimal.valueOf((i + 1) * indexSize).toBigInteger();
				int compareTo = startIndex.compareTo(endIndex);
				if (compareTo > 0) {
					BigInteger tmp = startIndex;
					startIndex = endIndex;
					endIndex = tmp;
				}
				else if (compareTo == 0) {
					endIndex = startIndex.add(BigInteger.ONE);
				}
				if (endIndex.compareTo(map.getIndexCount()) >= 0) {
					endIndex = map.getIndexCount();
				}
				FieldSelection fs = new FieldSelection();
				fs.addRange(startIndex, endIndex);
				AddressSet set = map.getAddressSet(fs);
				if (markers.intersects(set)) {
					newOverview.addRange(i, i);
				}
				startIndex = endIndex;
			}
		}

		overview = newOverview;
		return newOverview;
	}

	/**
	 * Get the tooltip for the marker at the specified index and address
	 * 
	 * @param addr address of item to navigate to
	 * @param x x location of cursor
	 * @param y y location of cursor
	 * 
	 * @return tool tip string, null if no tool tip
	 */
	public String getTooltip(Address addr, int x, int y) {
		if (markerDescriptor != null) {
			MarkerLocation loc = new MarkerLocation(this, mgr.getProgram(), addr, x, y);
			return markerDescriptor.getTooltip(loc);
		}
		return null;
	}

	@Override
	public boolean isDisplayedInNavigationBar() {
		return showNavigation;
	}

	@Override
	public boolean displayInMarkerBar() {
		return showMarkers;
	}

	@Override
	public boolean isColoringBackground() {
		return colorBackground;
	}

	@Override
	public void setColoringBackground(boolean b) {
		colorBackground = b;
		mgr.markersChanged(program);
	}

	public ProgramLocation getProgramLocation(int y, int height, AddressIndexMap map, int x) {

		assertSwing();
		if (overview == null) {
			return null;
		}

		ProgramLocation loc = null;
		if (overviewContains(y)) {
			y -= MARKER_HEIGHT - 1;
			if (y < 0) {
				y = 0;
			}

			BigDecimal bigHeight = BigDecimal.valueOf(height);
			BigInteger bigStarty = BigInteger.valueOf(y);
			BigInteger bigEndy = BigInteger.valueOf(y + MARKER_HEIGHT);
			BigInteger numIndexes = map.getIndexCount();
			BigInteger numIndexesMinus1 = numIndexes.subtract(BigInteger.ONE);
			numIndexesMinus1.max(BigInteger.ZERO);

			BigInteger start = getIndex(bigStarty, bigHeight, numIndexes, numIndexesMinus1);
			BigInteger end = getIndex(bigEndy, bigHeight, numIndexes, numIndexesMinus1);

			FieldSelection fs = new FieldSelection();
			fs.addRange(start, end.add(BigInteger.ONE));
			AddressSet set = map.getAddressSet(fs);

			if (set.isEmpty()) {
				return null;
			}

			Address addr = markers.findFirstAddressInCommon(set);
			if (addr == null) {
				addr = set.getMinAddress();
			}
			if (markerDescriptor != null) {
				MarkerLocation ml = new MarkerLocation(this, mgr.getProgram(), addr, x, y);
				loc = markerDescriptor.getProgramLocation(ml);
			}

			if (loc == null) {
				loc = new ProgramLocation(mgr.getProgram(), addr);
			}
		}
		return loc;

	}

	private BigInteger getIndex(BigInteger bigStarty, BigDecimal bigHeight, BigInteger numIndexes,
			BigInteger numIndexesMinus1) {
		BigDecimal total = new BigDecimal(bigStarty.multiply(numIndexes));
		BigDecimal div = total.divideToIntegralValue(bigHeight);
		BigInteger index = div.toBigInteger();

		index = index.min(numIndexesMinus1);
		return index;
	}

	private boolean overviewContains(int index) {
		for (int i = 0; i < MARKER_HEIGHT; i++) {
			if (overview.contains(index - i)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean isActive() {
		return active;
	}

	@Override
	public void setActive(boolean state) {
		active = state;
		mgr.markersChanged(program);
	}

	@Override
	public AddressSet getAddressSet() {
		assertSwing();
		return markers.getCombinedAddressSet();
	}

	@Override
	public Address getMinAddress() {
		assertSwing();
		return markers.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		assertSwing();
		return markers.getMaxAddress();
	}

	@Override
	public boolean intersects(Address start, Address end) {
		assertSwing();
		return markers.intersects(start, end);
	}

	// Note: reading and writing to 'markers' is synchronized via the Swing thread
	private void assertSwing() {
		Swing.assertSwingThread(
			"Calls to the MarkerSetImpl must be made on the Swing thread");
	}

	@Override
	public String toString() {
		return Json.toString(this, "active", "colorBackground", "markers");
	}
}
