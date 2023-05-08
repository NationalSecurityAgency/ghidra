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
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.Icon;
import javax.swing.JToolTip;
import javax.swing.event.ChangeListener;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.PopupWindow;
import generic.theme.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.ColorUtils.ColorBlender;
import ghidra.util.datastruct.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

/**
 * Manages markers on the marker panel (left side) and the overview panel (right side).
 */
public class MarkerManager implements MarkerService {

	final static String POPUP_WINDOW_NAME = "Marker ToolTip Window";
	final static int MAX_TOOLTIP_LINES = 10;

	/**
	 * For any given group name there can be any number of programs that have that group name mapped
	 * to a MarkerSet. This structure allows for a lookup of the marker set group to get a mapping
	 * of program->marker set.
	 */
	private Map<String, Map<Program, MarkerSetImpl>> programMarkersByGroup =
		LazyMap.lazyMap(new HashMap<>(), () -> new HashMap<>());

	/**
	 * A cache of programs to marker sets so that clients can install marker sets on a
	 * program-by-program basis
	 */
	private MarkerSetCache markerSetCache = new MarkerSetCache();

	/** Buffers requests to repaint and notify of marker changes */
	private SwingUpdateManager updater;
	private GoToService goToService;

	private MarkerMarginProvider primaryMarginProvider;
	private WeakSet<MarkerMarginProvider> marginProviders =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private MarkerOverviewProvider primaryOverviewProvider;
	private WeakSet<MarkerOverviewProvider> overviewProviders =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private final PluginTool tool;
	private final String owner;

	private PopupWindow popupWindow;

	private List<ChangeListener> listeners = new ArrayList<>();
	private MarkerClickedListener markerClickedListener = null;
	private ThemeListener themeListener = e -> themeChanged(e);

	public MarkerManager(Plugin plugin) {
		this(plugin.getName(), plugin.getTool());
	}

	public MarkerManager(String owner, PluginTool tool) {
		this.tool = tool;
		this.owner = owner;

		updater = new SwingUpdateManager(100, 60000, () -> {
			marginProviders.forEach(provider -> provider.repaintPanel());
			overviewProviders.forEach(provider -> provider.repaintPanel());
			notifyListeners();
		});

		primaryMarginProvider = createMarginProvider();
		primaryOverviewProvider = createOverviewProvider();

		Gui.addThemeListener(themeListener);
	}

	private void themeChanged(ThemeEvent e) {
		if (e instanceof ColorChangedThemeEvent) {
			markerSetCache.clearColors();
		}
	}

	private void programClosed(Program program) {
		Map<String, Map<Program, MarkerSetImpl>> values = programMarkersByGroup;
		Collection<Map<Program, MarkerSetImpl>> valueValues = values.values();
		for (Map<Program, MarkerSetImpl> map : valueValues) {
			map.remove(program);
		}
	}

	@Override
	public MarkerSet createAreaMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color) {
		AreaMarkerSet mgr = new AreaMarkerSet(this, name, markerDescription, priority, showMarkers,
			showNavigation, colorBackground, color, program);
		insertMarkers(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet createAreaMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, boolean isPreferred) {
		AreaMarkerSet mgr = new AreaMarkerSet(this, name, markerDescription, priority, showMarkers,
			showNavigation, colorBackground, color, isPreferred, program);
		insertMarkers(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, Icon icon) {
		MarkerSetImpl markers = new PointMarkerSet(this, name, markerDescription, priority,
			showMarkers, showNavigation, colorBackground, color, icon, program);
		insertMarkers(markers, program);
		return markers;
	}

	@Override
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, Icon icon, boolean isPreferred) {
		MarkerSetImpl markers = new PointMarkerSet(this, name, markerDescription, priority,
			showMarkers, showNavigation, colorBackground, color, icon, isPreferred, program);
		insertMarkers(markers, program);
		return markers;
	}

	@Override
	public MarkerSet getMarkerSet(String name, Program program) {
		if (name == null) {
			throw new NullPointerException("Marker set name cannot be null.");
		}

		if (program == null) {
			throw new NullPointerException("Program cannot be null.");
		}

		return markerSetCache.get(program).getByName(name);
	}

	@Override
	public void removeMarker(MarkerSet markers, Program program) {
		if (program == null) {
			throw new NullPointerException("Cannot remove marker set for a null program.");
		}

		doRemoveMarker(markers, program);
		refreshActionList(program);
		markersChanged(program);
	}

	private void refreshActionList(Program program) {
		overviewProviders.forEach(provider -> provider.refreshActionList(program));
	}

	private void doRemoveMarker(MarkerSet markers, Program program) {
		if (markers == null || program == null) {
			return;
		}

		// per-program list
		MarkerSetCacheEntry entry = markerSetCache.get(program);
		if (entry == null) {
			return;
		}
		entry.removeSet(markers);

		// per-group list
		// We need to find the marker by searching through the map of maps (when used in a
		// group setting the marker manager will be mapped directly to one program)
		Collection<Map<Program, MarkerSetImpl>> values = programMarkersByGroup.values();
		for (Map<Program, MarkerSetImpl> map : values) {
			MarkerSetImpl markerSetImpl = map.get(program);
			if (markerSetImpl == markers) {
				map.clear();
				break;
			}
		}

	}

	public MarkerMarginProvider getMarginProvider() {
		return primaryMarginProvider;
	}

	@Override
	public MarkerMarginProvider createMarginProvider() {
		MarkerMarginProvider provider = new MarkerMarginProvider(this);
		marginProviders.add(provider);
		return provider;
	}

	public OverviewProvider getOverviewProvider() {
		return primaryOverviewProvider;
	}

	@Override
	public MarkerOverviewProvider createOverviewProvider() {
		MarkerOverviewProvider provider = new MarkerOverviewProvider(owner, tool, this);
		overviewProviders.add(provider);
		return provider;
	}

	public void dispose() {
		Gui.removeThemeListener(themeListener);
		updater.dispose();
		markerSetCache.clear();
		overviewProviders.forEach(provider -> provider.dispose());
	}

	void navigateTo(Navigatable navigatable, Program program, int x, int y, int viewHeight,
			AddressIndexMap addrMap) {
		MarkerSetCacheEntry entry = markerSetCache.get(program);

		ProgramLocation loc = entry.getProgramLocation(y, viewHeight, addrMap, x);
		getGoToService();
		if (loc != null && goToService != null) {
			goToService.goTo(navigatable, loc, loc.getProgram());
		}
	}

	void paintNavigation(Program program, Graphics g, NavigationPanel panel,
			AddressIndexMap addrMap) {
		if (addrMap == null) {
			return;
		}

		MarkerSetCacheEntry entry = markerSetCache.get(program);
		if (entry == null) {
			return;
		}
		entry.paintNavigation(g, panel.getViewHeight(), panel.getWidth(), addrMap);
	}

	void paintMarkers(Program program, Graphics g, VerticalPixelAddressMap pixmap,
			AddressIndexMap addrMap) {
		MarkerSetCacheEntry entry = markerSetCache.get(program);
		if (entry == null) {
			return;
		}
		entry.paintMarkers(g, pixmap, addrMap);
	}

	void showToolTipPopup(MouseEvent event, String tip) {
		if (tip == null) {
			return;
		}

		JToolTip toolTip = new JToolTip();
		toolTip.setTipText("<html><font size=\"" + 4 + "\">" + tip);

		if (popupWindow != null) {
			popupWindow.dispose();
		}
		popupWindow = new PopupWindow(event.getComponent(), toolTip);
		popupWindow.setWindowName(MarkerManager.POPUP_WINDOW_NAME);
		popupWindow.showPopup(event);
	}

	/*testing*/ String generateToolTip(MouseEvent event) {
		return primaryMarginProvider.generateToolTip(event);
	}

	List<String> getMarkerTooltipLines(Program program, int y, int x, Address minAddr,
			Address maxAddr) {
		MarkerSetCacheEntry entry = markerSetCache.get(program);
		return entry == null ? List.of() : entry.getTooltipLines(y, x, minAddr, maxAddr);
	}

	static String getMarkerToolTip(MarkerSetImpl marker, Address a, int x, int y) {
		String tip = marker.getTooltip(a, x, y);
		if (tip == null) {
			tip = marker.getName();
		}
		return tip;
	}

	List<MarkerSetImpl> copyMarkerSets(Program program) {
		MarkerSetCacheEntry entry = markerSetCache.get(program);
		return entry == null ? Collections.emptyList() : entry.copyList();
	}

	/**
	 * Call to signal that the markers for a given program have changed in some way, such as being
	 * removed, changing colors or the active state being changed
	 *
	 * @param p the program associated with the markers
	 */
	void markersChanged(Program p) {
		MarkerSetCacheEntry entry = markerSetCache.get(p);
		if (entry != null) {
			entry.colorCache.clear();
		}
		updater.update();
	}

	private void insertMarkers(MarkerSetImpl markers, Program program) {
		if (program == null) {
			throw new AssertException("Program cannot be null");
		}

		MarkerSetCacheEntry entry = markerSetCache.get(program);
		if (entry == null) {
			return; // no list means deprecated usage
		}

		entry.insertSet(markers);

		refreshActionList(program);
	}

	void updateMarkerSets(Program program, boolean updateMarkers, boolean updateNavigation,
			boolean updateNow) {

		MarkerSetCacheEntry entry = markerSetCache.get(program);
		if (entry == null) {
			return;
		}
		entry.updateView(updateMarkers, updateNavigation);

		if (updateNow) {
			updater.updateNow();
		}
		else {
			updater.update();
		}
	}

	@Override
	public void addChangeListener(ChangeListener listener) {
		listeners.remove(listener);
		listeners.add(listener);
	}

	@Override
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void notifyListeners() {
		for (ChangeListener listener : listeners) {
			listener.stateChanged(null);
		}
	}

	MarkerSetImpl getMarkerSet(Program program, Address addr) {
		MarkerSetCacheEntry entry = markerSetCache.get(program);
		return entry.getMarkerSetAt(addr);
	}

	@Override
	public void setMarkerForGroup(String groupName, MarkerSet ms, Program program) {
		if (!(ms instanceof MarkerSetImpl)) {
			throw new IllegalArgumentException("Invalid marker set provided");
		}

		Map<Program, MarkerSetImpl> markersByProgram = programMarkersByGroup.get(groupName);
		MarkerSetImpl previousMarkers = markersByProgram.get(program);
		MarkerSetImpl markers = (MarkerSetImpl) ms;
		if (markers == previousMarkers) {
			return;
		}

		removeMarker(previousMarkers, program);
		markersByProgram.put(program, markers);
		insertMarkers(markers, program);
	}

	@Override
	public boolean isActiveMarkerForGroup(String groupName, MarkerSet markerSet, Program program) {
		Map<Program, MarkerSetImpl> markersByProgram = programMarkersByGroup.get(groupName);
		MarkerSetImpl previousMarkers = markersByProgram.get(program);
		return markerSet == previousMarkers;
	}

	@Override
	public void removeMarkerForGroup(String groupName, MarkerSet markers, Program program) {
		Map<Program, MarkerSetImpl> markersByProgram = programMarkersByGroup.get(groupName);
		MarkerSet previousMarkers = markersByProgram.get(program);

		if (markers == previousMarkers) {
			markersByProgram.remove(program);
			removeMarker(previousMarkers, program);
		}
	}

	@Override
	public Color getBackgroundColor(Program program, Address address) {
		return getBackgroundColor(program, markerSetCache.get(program), address);
	}

	private Color getBackgroundColor(Program program, MarkerSetCacheEntry entry, Address address) {
		return entry == null ? null : entry.getBackgroundColor(address);
	}

	public GoToService getGoToService() {
		if (goToService == null) {
			goToService = tool.getService(GoToService.class);
		}
		return goToService;
	}

	public void setGoToService(GoToService goToService) {
		this.goToService = goToService;
	}

	@Override
	public void setMarkerClickedListener(MarkerClickedListener listener) {
		if (listener != null && markerClickedListener != null) {
			throw new IllegalStateException(
				"Attempted to assign more than one MarkerClickedListener!");
		}
		markerClickedListener = listener;
	}

	public MarkerClickedListener getMarkerClickedListener() {
		return markerClickedListener;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A LRU map that maintains <i>insertion-order</i> iteration over the elements. As new items are
	 * added, the older items will be removed from this map the given plugin.
	 */
	private static class AddressColorCache extends FixedSizeHashMap<Address, Color> {
		private final static int MAX_SIZE = 50;

		AddressColorCache() {
			super(MAX_SIZE, MAX_SIZE);
		}
	}

	private class MarkerSetCache {
		Map<Program, MarkerSetCacheEntry> map = new HashMap<>();

		MarkerSetCacheEntry get(Program program) {
			if (program == null || program.isClosed()) {
				return null;
			}
			MarkerSetCacheEntry entry = map.computeIfAbsent(program, this::newEntry);
			if (program.isClosed()) {
				map.remove(program);
				return null;
			}
			return entry;
		}

		void clearColors() {
			for (MarkerSetCacheEntry entry : map.values()) {
				entry.clearColors();
			}
		}

		public void clear() {
			map.clear();
		}

		private MarkerSetCacheEntry newEntry(Program program) {
			return new MarkerSetCacheEntry(this, program);
		}

		private void programClosed(Program program) {
			map.remove(program);
			MarkerManager.this.programClosed(program);
		}
	}

	private static class MarkerSetCacheEntry {
		private final List<MarkerSetImpl> markerSets = new ArrayList<>();
		private final AddressColorCache colorCache = new AddressColorCache();
		private final ColorBlender blender = new ColorBlender();

		private final MarkerSetCache cache;
		private final Program program;
		private final DomainObjectClosedListener closeListener = this::programClosed;

		public MarkerSetCacheEntry(MarkerSetCache cache, Program program) {
			this.cache = cache;
			this.program = program;
			/**
			 * Use this close listener approach instead of plugin events, since we don't get a
			 * ProgramClosedPluginEvent when a trace view is closed, but we can listen for its
			 * domain object closing, which works for plain programs, too.
			 */
			program.addCloseListener(closeListener);
		}

		void clearColors() {
			colorCache.clear();
		}

		private void programClosed() {
			program.removeCloseListener(closeListener);
			cache.programClosed(program);
		}

		MarkerSetImpl getByName(String name) {
			for (MarkerSetImpl set : markerSets) {
				if (name.equals(set.getName())) {
					return set;
				}
			}
			return null;
		}

		void removeSet(MarkerSet set) {
			markerSets.remove(set);
		}

		void insertSet(MarkerSetImpl set) {
			int index = Collections.binarySearch(markerSets, set);
			if (index < 0) {
				index = -(index + 1);
			}
			markerSets.add(index, set);
		}

		ProgramLocation getProgramLocation(int y, int viewHeight, AddressIndexMap addrMap, int x) {
			for (MarkerSetImpl markers : IterableUtils.reversedIterable(markerSets)) {
				if (markers.isActive()) {
					ProgramLocation loc = markers.getProgramLocation(y, viewHeight, addrMap, x);
					if (loc != null) {
						return loc;
					}
				}
			}
			return null;
		}

		void paintNavigation(Graphics g, int viewHeight, int width, AddressIndexMap addrMap) {
			for (MarkerSetImpl markers : markerSets) {
				if (markers.active) {
					markers.paintNavigation(g, viewHeight, width, addrMap);
				}
			}
		}

		void paintMarkers(Graphics g, VerticalPixelAddressMap pixmap, AddressIndexMap addrMap) {
			int count = 0;
			for (MarkerSetImpl markers : markerSets) {
				count++;
				if (markers.active) {
					markers.paintMarkers(g, count++, pixmap, addrMap);
				}
			}
		}

		void updateView(boolean updateMakers, boolean updateNavigation) {
			for (MarkerSetImpl markers : markerSets) {
				markers.updateView(updateMakers, updateNavigation);
			}
		}

		MarkerSetImpl getMarkerSetAt(Address address) {
			for (MarkerSetImpl markers : IterableUtils.reversedIterable(markerSets)) {
				if (markers.displayInMarkerBar() && markers.contains(address)) {
					return markers;
				}
			}
			return null;
		}

		Color getBackgroundColor(Address address) {
			if (colorCache.containsKey(address)) {
				return colorCache.get(address);
			}
			blender.clear();
			for (MarkerSetImpl markers : markerSets) {
				if (markers.isActive() && markers.isColoringBackground() &&
					markers.contains(address)) {
					blender.add(markers.getMarkerColor());
				}
			}
			Color color = blender.getColor(null);
			colorCache.put(address, color);
			return color;
		}

		List<String> getTooltipLines(int y, int x, Address minAddr, Address maxAddr) {
			List<String> lines = new ArrayList<>();
			for (MarkerSetImpl markers : IterableUtils.reversedIterable(markerSets)) {
				if (!markers.displayInMarkerBar()) {
					continue;
				}
				AddressSet set = markers.getAddressSet();
				AddressSet intersection = set.intersectRange(minAddr, maxAddr);
				for (Address a : intersection.getAddresses(true)) {
					lines.add(getMarkerToolTip(markers, a, x, y));
					if (markers instanceof AreaMarkerSet) {
						break; // no more tooltips from this area 
					}
					if (lines.size() >= MAX_TOOLTIP_LINES) {
						lines.add("...");
						return lines;
					}
				}
			}
			return lines;
		}

		List<MarkerSetImpl> copyList() {
			return new ArrayList<>(markerSets);
		}
	}
}
