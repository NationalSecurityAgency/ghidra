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
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import org.apache.commons.collections4.map.LazyMap;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.PopupWindow;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.MarkerLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

/**
 * Manages markers on the marker panel (left side) and the overview
 * panel (right side).
 */
public class MarkerManager implements MarkerService {

	private final static String POPUP_WINDOW_NAME = "Bookmark ToolTip Window";
	private final static int MAX_TOOLTIP_LINES = 10;

	private MarkerPanel markPanel;
	private NavigationPanel navigationPanel;
	private MarkerActionList actionList;
	private VerticalPixelAddressMap pixmap;
	private AddressIndexMap addrMap;

	/**
	 * For any given group name there can be any number of programs that have that group name
	 * mapped to a MarkerSet.   This structure allows for a lookup of the marker set group to
	 * get a mapping of program->marker set.
	 */
	private Map<String, Map<Program, MarkerSetImpl>> groupToProgramMarkerMap;
	private List<MarkerSetImpl> currentMarkerSets;

	/**
	 * A cache of programs to marker sets so that clients can install marker sets on a
	 * program-by-program basis
	 */
	private Map<Program, List<MarkerSetImpl>> markerSetCache =
		LazyMap.lazyMap(new HashMap<>(), () -> new ArrayList<>());

	private SwingUpdateManager updateMgr;
	private GoToService goToService;
	private Navigatable navigatable;

	private MarginProvider marginProvider;
	private OverviewProvider overviewProvider;

	private PluginTool tool;
	private String owner; // owner of the actions
	private Program currentProgram;

	private Map<Program, AddressColorCache> colorCache =
		LazyMap.lazyMap(new HashMap<>(), () -> new AddressColorCache());

	private PopupWindow popupWindow;

	private List<ChangeListener> listeners = new ArrayList<>();

	public MarkerManager(Plugin ownerPlugin) {
		this(ownerPlugin.getName(), ownerPlugin.getTool());
	}

	public MarkerManager(String owner, PluginTool tool) {
		this.owner = owner;
		this.tool = tool;

		currentMarkerSets = Collections.emptyList();

		updateMgr = new SwingUpdateManager(100, 60000, () -> {
			markPanel.repaint();
			navigationPanel.repaint();
			notifyListeners();
		});

		navigationPanel = new NavigationPanel(this);
		navigationPanel.setPreferredSize(new Dimension(16, 1));
		navigationPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				updateMarkerSets(true, true, true);
			}
		});
		overviewProvider = new MyOverviewProvider();

		markPanel = new MarkerPanel(this);
		markPanel.setPreferredSize(new Dimension(16, 1));
		marginProvider = new MyMarginProvider();

		actionList = new MarkerActionList();
		groupToProgramMarkerMap = new HashMap<>();
	}

	void programClosed(Program program) {
		markerSetCache.remove(program);

		Map<String, Map<Program, MarkerSetImpl>> values = groupToProgramMarkerMap;
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
		insertManager(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet createAreaMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, boolean isPreferred) {
		AreaMarkerSet mgr = new AreaMarkerSet(this, name, markerDescription, priority, showMarkers,
			showNavigation, colorBackground, color, isPreferred);
		insertManager(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, ImageIcon icon) {
		MarkerSetImpl mgr = new PointMarkerSet(this, name, markerDescription, priority, showMarkers,
			showNavigation, colorBackground, color, icon);
		insertManager(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, ImageIcon icon, boolean isPreferred) {
		MarkerSetImpl mgr = new PointMarkerSet(this, name, markerDescription, priority, showMarkers,
			showNavigation, colorBackground, color, icon, isPreferred);
		insertManager(mgr, program);
		return mgr;
	}

	@Override
	public MarkerSet getMarkerSet(String name, Program program) {
		if (name == null) {
			throw new NullPointerException("Marker set name cannot be null.");
		}

		if (program == null) {
			throw new NullPointerException("Program cannot be null.");
		}

		List<MarkerSetImpl> list = markerSetCache.get(program);
		for (MarkerSetImpl set : list) {
			if (name.equals(set.getName())) {
				return set;
			}
		}
		return null;
	}

	@Override
	public void removeMarker(MarkerSet markerManager, Program program) {
		if (program == null) {
			throw new NullPointerException("Cannot remove marker set for a null program.");
		}

		doRemoveMarker(markerManager, program);
		actionList.refresh();
		update();
	}

	private void doRemoveMarker(MarkerSet markerSet, Program program) {
		if (markerSet == null || program == null) {
			return;
		}

		// per-program list
		List<MarkerSetImpl> list = markerSetCache.get(program);
		list.remove(markerSet);

		// per-group list
		// We need to find the marker by searching through the map of maps (when used in a
		// group setting the marker manager will be mapped directly to one program)
		Collection<Map<Program, MarkerSetImpl>> values = groupToProgramMarkerMap.values();
		for (Map<Program, MarkerSetImpl> map : values) {
			MarkerSetImpl markerSetImpl = map.get(program);
			if (markerSetImpl == markerSet) {
				map.clear();
				break;
			}
		}

	}

	public MarginProvider getMarginProvider() {
		return marginProvider;
	}

	public OverviewProvider getOverviewProvider() {
		return overviewProvider;
	}

	/**
	 * Set the program for the marker sets.
	 * @param program may be null
	 */
	public void setProgram(Program program) {
		this.currentProgram = program;
		if (program == null) {
			currentMarkerSets = Collections.emptyList();
			updateMgr.update();
			return;
		}

		colorCache.get(program).clear();
		setCurrentMarkerSets(program);
		actionList.refresh();

		updateMgr.update();
	}

	public void dispose() {
		updateMgr.dispose();
		actionList.dispose();
		currentMarkerSets.clear();
		markerSetCache.clear();
		colorCache.clear();
	}

	void navigateTo(int x, int y) {
		int viewHeight = navigationPanel.getHeight() - MarkerSetImpl.MARKER_HEIGHT;
		for (int i = currentMarkerSets.size() - 1; i >= 0; i--) {
			MarkerSetImpl marker = currentMarkerSets.get(i);
			if (marker.isActive()) {
				GoToService service = getGoToService();
				ProgramLocation loc = marker.getProgramLocation(y, viewHeight, addrMap, x);
				if (loc != null && service != null) {
					service.goTo(navigatable, loc, loc.getProgram());
					break;
				}
			}
		}
	}

	void paintMarkers(Graphics g) {
		Iterator<MarkerSetImpl> iter = currentMarkerSets.iterator();
		int count = 0;
		while (iter.hasNext()) {
			MarkerSetImpl marker = iter.next();
			if (marker.isActive()) {
				marker.paintMarkers(g, count++, pixmap, addrMap);
			}
		}
	}

	void paintNavigation(Graphics g, NavigationPanel panel) {
		if (addrMap == null) {
			return;
		}
		int viewHeight = panel.getHeight() - MarkerSetImpl.MARKER_HEIGHT;
		Iterator<MarkerSetImpl> iter = currentMarkerSets.iterator();
		while (iter.hasNext()) {
			MarkerSetImpl mgr = iter.next();
			if (mgr.active) {
				mgr.paintNavigation(g, viewHeight, panel, addrMap);
			}
		}
	}

	/**
	 * Method getTooltip for object under cursor
	 * @param event the event containing the cursor coordinates
	 * @return tool tip string for object under cursor
	 */
	String getTooltip(MouseEvent event) {

		String tip = generateToolTip(event);
		if (tip == null) {
			return null;
		}

		JToolTip toolTip = new JToolTip();
		toolTip.setTipText("<html><font size=\"" + 4 + "\">" + tip);

		if (popupWindow != null) {
			popupWindow.dispose();
		}
		popupWindow = new PopupWindow(event.getComponent(), toolTip);
		popupWindow.setWindowName(POPUP_WINDOW_NAME);
		popupWindow.showPopup(event);

		return null; // signal not to show a Java tooltip
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
		List<String> lines = new ArrayList<>();
		for (int i = currentMarkerSets.size() - 1; i >= 0; i--) {

			MarkerSetImpl marker = currentMarkerSets.get(i);
			if (!marker.displayInMarkerBar()) {
				continue;
			}

			AddressSet set = marker.getAddressSet();
			AddressSet intersection = set.intersect(new AddressSet(layoutAddress, endAddr));
			for (Address a : intersection.getAddresses(true)) {
				lines.add(getMarkerToolTip(marker, a, x, y));

				if (marker instanceof AreaMarkerSet) {
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

	private String getMarkerToolTip(MarkerSetImpl marker, Address a, int x, int y) {
		String markerTip = marker.getTooltip(a, x, y);
		if (markerTip == null) {
			markerTip = marker.getName();
		}
		return markerTip;
	}

	private String toHTML(List<String> lines) {
		if (lines.isEmpty()) {
			return null;
		}
		StringBuilder buffy = new StringBuilder("<html><font size=\"" + 4 + "\">");
		for (String string : lines) {
			buffy.append(string).append("<BR>");
		}
		return buffy.toString();
	}

	void update() {
		AddressColorCache addressColorCache = colorCache.get(currentProgram);
		addressColorCache.clear();
		updateMgr.update();
	}

	private void insertManager(MarkerSetImpl mgr, Program program) {
		if (program == null) {
			throw new AssertException("Program cannot be null");
		}

		List<MarkerSetImpl> markerSetList = markerSetCache.get(program);
		if (markerSetList == null) {
			return; // no list means deprecated usage
		}

		int index = Collections.binarySearch(markerSetList, mgr);
		if (index < 0) {
			index = -(index + 1);
		}

		markerSetList.add(index, mgr);
		actionList.refresh();
	}

	private void setCurrentMarkerSets(Program program) {
		List<MarkerSetImpl> markerSetList = markerSetCache.get(program);

		// determine if we are switching lists
		boolean switchingLists = (markerSetList != currentMarkerSets);
		if (!switchingLists) {
			return;
		}

		currentMarkerSets = markerSetList;
		Collections.sort(currentMarkerSets);
	}

	private Address getAddress(int y) {
		if (pixmap == null) {
			return null;
		}
		int i = pixmap.findLayoutAt(y);
		return pixmap.getLayoutAddress(i);
	}

	private void updateMarkerSets(boolean updateMarkers, boolean updateNavigation,
			boolean updateNow) {
		Iterator<MarkerSetImpl> iter = currentMarkerSets.iterator();
		while (iter.hasNext()) {
			MarkerSetImpl marker = iter.next();
			marker.updateView(updateMarkers, updateNavigation);
		}

		if (updateNow) {
			updateMgr.updateNow();
		}
		else {
			updateMgr.update();
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

	private MarkerSetImpl getMarkerSet(Address addr) {
		for (int i = currentMarkerSets.size() - 1; i >= 0; i--) {
			MarkerSetImpl marker = currentMarkerSets.get(i);
			if (marker.displayInMarkerBar() && marker.contains(addr)) {
				return marker;
			}
		}
		return null;
	}

	Program getProgram() {
		return currentProgram;
	}

	@Override
	public void setMarkerForGroup(String groupName, MarkerSet ms, Program program) {
		if (!(ms instanceof MarkerSetImpl)) {
			throw new IllegalArgumentException("Invalid marker set provided");
		}

		Map<Program, MarkerSetImpl> programToMarkerMap = groupToProgramMarkerMap.get(groupName);
		if (programToMarkerMap == null) {
			programToMarkerMap = new HashMap<>();
			groupToProgramMarkerMap.put(groupName, programToMarkerMap);
		}

		MarkerSetImpl previousSet = programToMarkerMap.get(program);
		MarkerSetImpl markerSet = (MarkerSetImpl) ms;

		if (markerSet == previousSet) {
			return;
		}

		removeMarker(previousSet, program);
		programToMarkerMap.put(program, markerSet);
		insertManager(markerSet, program);
	}

	@Override
	public void removeMarkerForGroup(String groupName, MarkerSet markerSet, Program program) {
		Map<Program, MarkerSetImpl> programToMarkerMap = groupToProgramMarkerMap.get(groupName);
		MarkerSet currentMarkerSet = programToMarkerMap.get(program);

		if (markerSet == currentMarkerSet) {
			programToMarkerMap.remove(program);
			removeMarker(currentMarkerSet, program);
		}
	}

	@Override
	public Color getBackgroundColor(Address address) {
		return getBackgroundColor(currentProgram, currentMarkerSets, address);
	}

	public Color getBackgroundColor(Program program, Address address) {
		return getBackgroundColor(program, markerSetCache.get(program), address);
	}

	private Color getBackgroundColor(Program program, List<MarkerSetImpl> markerSets,
			Address address) {
		AddressColorCache addressColorCache = colorCache.get(currentProgram);
		if (addressColorCache.containsKey(address)) {
			return addressColorCache.get(address);
		}

		Color color = null;
		for (int index = markerSets.size() - 1; index >= 0; index--) {
			MarkerSet marker = markerSets.get(index);
			if (marker.isActive() && marker.isColoringBackground() && marker.contains(address)) {
				color = marker.getMarkerColor();
				break;
			}
		}

		if (color != null) {
			addressColorCache.put(address, color);
		}
		return color;
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

	public void setNavigatable(Navigatable navigatable) {
		this.navigatable = navigatable;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Marker Option Menu - controls the visibility of the various markers.
	 */
	class MarkerActionList implements OptionsChangeListener {

		private ArrayList<DockingAction> actions = new ArrayList<>();
		private ToolOptions listOptions;

		MarkerActionList() {
			initOptions();
			refresh();
		}

		private void initOptions() {
			listOptions = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_NAVIGATION_MARKERS);

			listOptions.removeOptionsChangeListener(this);
			listOptions.addOptionsChangeListener(this);
		}

		@Override
		public void optionsChanged(ToolOptions options, String name, Object oldValue,
				Object newValue) {
			for (DockingAction action : actions) {
				if (action instanceof ActivateMarkerAction) {
					((ActivateMarkerAction) action).optionsChanged();
				}
				if (action instanceof ActivateMarkerGroupAction) {
					((ActivateMarkerGroupAction) action).optionsChanged();
				}
			}
		}

		void refresh() {
			SystemUtilities.runSwingLater(() -> doRefresh());
		}

		private void doRefresh() {
			if (tool == null || currentProgram == null) {
				return;
			}

			for (DockingAction action : actions) {
				tool.removeAction(action);
			}
			actions.clear();

			ArrayList<MarkerSetImpl> list = new ArrayList<>();
			for (MarkerSetImpl mgr : currentMarkerSets) {
				list.add(mgr);
			}

			// separate the marker sets into grouped and non-grouped
			List<List<MarkerSetImpl>> groupsList = extractManagerGroups(list);
			Collections.sort(groupsList,
				(ms1, ms2) -> ms1.get(0).getName().compareTo(ms2.get(0).getName()));
			for (List<MarkerSetImpl> group : groupsList) {
				ActivateMarkerGroupAction action =
					new ActivateMarkerGroupAction(owner, group, navigationPanel, listOptions);
				actions.add(action);
				tool.addAction(action);
			}

			Collections.sort(list, (ms1, ms2) -> ms1.getName().compareTo(ms2.getName()));
			for (MarkerSetImpl mgr : list) {
				ActivateMarkerAction action =
					new ActivateMarkerAction(owner, mgr, navigationPanel, listOptions);
				actions.add(action);
				tool.addAction(action);
			}

			navigationPanel.repaint();
		}

		/** 
		 * Creates a list of elements that are in the same logical group and removes those
		 * elements from the given list.
		 */
		private List<List<MarkerSetImpl>> extractManagerGroups(List<MarkerSetImpl> fromList) {
			// empty the original list for grouping...
			Map<String, List<MarkerSetImpl>> nameToManagerMap = new HashMap<>();
			for (Iterator<MarkerSetImpl> iterator = fromList.iterator(); iterator.hasNext();) {
				MarkerSetImpl markerSetImpl = iterator.next();
				String name = markerSetImpl.getName();
				List<MarkerSetImpl> subList = nameToManagerMap.get(name);
				if (subList == null) {
					subList = new ArrayList<>();
					nameToManagerMap.put(name, subList);
				}
				subList.add(markerSetImpl);
				iterator.remove();
			}

			// ...now repopulate the original list with all non-group managers and put the groups
			// in their own list
			List<List<MarkerSetImpl>> groupList = new ArrayList<>(fromList.size());
			Set<Entry<String, List<MarkerSetImpl>>> entrySet = nameToManagerMap.entrySet();
			for (Entry<String, List<MarkerSetImpl>> entry : entrySet) {
				List<MarkerSetImpl> listValue = entry.getValue();

				// non-group list
				if (listValue.size() == 1) {
					fromList.add(listValue.get(0));
				}
				// group list
				else {
					groupList.add(listValue);
				}
			}

			return groupList;
		}

		void dispose() {
			listOptions.removeOptionsChangeListener(this);
			Iterator<DockingAction> iter = actions.iterator();
			while (iter.hasNext()) {
				DockingAction action = iter.next();
				tool.removeAction(action);
			}
		}

	}

	private static class ActivateMarkerAction extends ToggleDockingAction {

		private MarkerSetImpl mgr;
		private NavigationPanel panel;
		private Options options;

		ActivateMarkerAction(String owner, MarkerSetImpl mgr, NavigationPanel panel,
				Options options) {
			super(mgr.getName(), owner);
			this.mgr = mgr;
			this.panel = panel;
			this.options = options;
			HelpLocation helpLocation = new HelpLocation(HelpTopics.CODE_BROWSER, "Markers");
			options.registerOption(mgr.getName(), true, helpLocation,
				"This options enables/disables the display of " + mgr.getName() + " marker types.");

			setEnabled(true);
			setSelected(mgr.active);
			setPopupMenuData(new MenuData(new String[] { mgr.getName() }, mgr.getNavIcon(), null));

			boolean isEnabled = isOptionEnabled();
			setSelected(isEnabled);
			mgr.setActive(isEnabled);
			HelpLocation location = new HelpLocation(HelpTopics.CODE_BROWSER, "Markers");
			setHelpLocation(location);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Object contextObject = context.getContextObject();
			return contextObject == panel;
		}

		void optionsChanged() {
			boolean selected = isOptionEnabled();
			if (selected != isSelected()) {
				setSelected(selected);
				mgr.setActive(selected);
			}
		}

		private boolean isOptionEnabled() {
			return options.getBoolean(mgr.getName(), true);

		}

		@Override
		public void actionPerformed(ActionContext context) {
			options.setBoolean(mgr.getName(), isSelected());
			mgr.setActive(isSelected());
		}
	}

	private static class ActivateMarkerGroupAction extends ToggleDockingAction {
		private List<MarkerSetImpl> managerList;
		private NavigationPanel panel;
		private Options options;

		ActivateMarkerGroupAction(String owner, List<MarkerSetImpl> managerList,
				NavigationPanel panel, Options options) {
			super(managerList.get(0).getName(), owner);
			this.managerList = managerList;
			this.panel = panel;
			this.options = options;
			HelpLocation helpLocation = new HelpLocation(HelpTopics.CODE_BROWSER, "Markers");
			options.registerOption(getName(), true, helpLocation,
				"This options enables/disables the display of " + getName() + " marker types.");

			setEnabled(true);
			setSelected(isActive());
			ImageIcon icon = managerList.get(0).getNavIcon();
			setPopupMenuData(new MenuData(new String[] { getName() }, icon));
			boolean isEnabled = isOptionEnabled();
			setSelected(isEnabled);
			setActive(isEnabled);
			setHelpLocation(helpLocation);
		}

		private void setActive(boolean active) {
			for (MarkerSetImpl manager : managerList) {
				manager.setActive(active);
			}
		}

		private boolean isActive() {
			for (MarkerSetImpl manager : managerList) {
				if (manager.isActive()) {
					return true;
				}
			}
			return false;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Object contextObject = context.getContextObject();
			return contextObject == panel;
		}

		void optionsChanged() {
			boolean selected = isOptionEnabled();
			if (selected != isSelected()) {
				setSelected(selected);
				setActive(selected);
			}
		}

		private boolean isOptionEnabled() {
			return options.getBoolean(getName(), true);

		}

		@Override
		public void actionPerformed(ActionContext context) {
			options.setBoolean(getName(), isSelected());
			setActive(isSelected());
		}
	}

	private class MyMarginProvider implements MarginProvider {
		@Override
		public JComponent getComponent() {
			return markPanel;
		}

		@Override
		public MarkerLocation getMarkerLocation(int x, int y) {
			Address addr = getAddress(y);
			if (addr == null) {
				return null;
			}
			MarkerSet marker = getMarkerSet(addr);
			return new MarkerLocation(marker, addr, x, y);
		}

		@Override
		public boolean isResizeable() {
			return false;
		}

		@Override
		public void setPixelMap(VerticalPixelAddressMap pixmap) {
			MarkerManager.this.pixmap = pixmap;
			updateMarkerSets(true, false, true);
		}
	}

	private class MyOverviewProvider implements OverviewProvider {

		@Override
		public JComponent getComponent() {
			return navigationPanel;
		}

		@Override
		public void setAddressIndexMap(AddressIndexMap map) {
			MarkerManager.this.addrMap = map;
			updateMarkerSets(true, true, false);
		}

	}

	/**
	 * A LRU map that maintains <i>insertion-order</i> iteration over the elements.  As new items 
	 * are added, the older items will be removed from this map the given plugin.
	 */
	static class AddressColorCache extends FixedSizeHashMap<Address, Color> {
		private final static int MAX_SIZE = 50;

		AddressColorCache() {
			super(MAX_SIZE, MAX_SIZE);
		}
	}

}
