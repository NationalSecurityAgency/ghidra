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

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.fieldpanel.FieldPanel;
import ghidra.GhidraOptions;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.MarkerService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

/**
 * The provider which renders the overview margin, usually placed outside the scrollbar to the right
 * of lisitng {@link FieldPanel}s.
 * 
 * <p>
 * These are managed by a {@link MarkerManager}. Obtain one via
 * {@link MarkerService#createOverviewProvider()}.
 */
public class MarkerOverviewProvider implements OverviewProvider {
	private final PluginTool tool;
	private final String owner;

	private final MarkerManager markerManager;
	private final NavigationPanel navigationPanel;

	private final MarkerActionList actionList;

	private Program program;

	MarkerOverviewProvider(String owner, PluginTool tool, MarkerManager markerManager) {
		this.tool = tool;
		this.owner = owner;

		this.markerManager = markerManager;
		this.navigationPanel = new NavigationPanel(markerManager);

		this.navigationPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				markerManager.updateMarkerSets(program, false, true, true);
			}
		});

		actionList = new MarkerActionList();
	}

	void dispose() {
		actionList.dispose();
	}

	public void repaintPanel() {
		navigationPanel.repaint();
	}

	@Override
	public JComponent getComponent() {
		return navigationPanel;
	}

	@Override
	public void setProgram(Program program, AddressIndexMap map) {
		this.program = program;

		navigationPanel.setProgram(program, map);
		markerManager.updateMarkerSets(program, true, true, false);
		actionList.refresh();
	}

	@Override
	public void setNavigatable(Navigatable navigatable) {
		navigationPanel.setNavigatable(navigatable);
	}

	void refreshActionList(Program p) {
		if (this.program != p) {
			return;
		}
		actionList.refresh();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Marker Option Menu - controls the visibility of the various markers.
	 */
	private class MarkerActionList implements OptionsChangeListener {

		private final List<DockingAction> actions = new ArrayList<>();
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
			Swing.runLater(this::doRefresh);
		}

		private void doRefresh() {
			for (DockingAction action : actions) {
				tool.removeAction(action);
			}
			actions.clear();

			if (program == null || program.isClosed()) {
				return;
			}

			List<MarkerSetImpl> list = markerManager.copyMarkerSets(program);

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
		 * Creates a list of elements that are in the same logical group and removes those elements
		 * from the given list.
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

			actions.forEach(a -> tool.removeAction(a));
		}
	}

	private static class ActivateMarkerAction extends ToggleDockingAction {

		private MarkerSetImpl markers;
		private NavigationPanel panel;
		private Options options;

		ActivateMarkerAction(String owner, MarkerSetImpl markers, NavigationPanel panel,
				Options options) {
			super(markers.getName(), owner);
			this.markers = markers;
			this.panel = panel;
			this.options = options;
			HelpLocation helpLocation = new HelpLocation(HelpTopics.CODE_BROWSER, "Markers");
			options.registerOption(markers.getName(), true, helpLocation,
				"This options enables/disables the display of " + markers.getName() +
					" marker types.");

			setEnabled(true);
			setSelected(markers.active);
			setPopupMenuData(
				new MenuData(new String[] { markers.getName() }, markers.getNavIcon(), null));

			boolean isEnabled = isOptionEnabled();
			setSelected(isEnabled);
			markers.setActive(isEnabled);
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
				markers.setActive(selected);
			}
		}

		private boolean isOptionEnabled() {
			return options.getBoolean(markers.getName(), true);

		}

		@Override
		public void actionPerformed(ActionContext context) {
			options.setBoolean(markers.getName(), isSelected());
			markers.setActive(isSelected());
		}
	}

	private static class ActivateMarkerGroupAction extends ToggleDockingAction {
		private List<MarkerSetImpl> markerSets;
		private NavigationPanel panel;
		private Options options;

		ActivateMarkerGroupAction(String owner, List<MarkerSetImpl> managerList,
				NavigationPanel panel, Options options) {
			super(managerList.get(0).getName(), owner);
			this.markerSets = managerList;
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
			for (MarkerSetImpl manager : markerSets) {
				manager.setActive(active);
			}
		}

		private boolean isActive() {
			return markerSets.stream().anyMatch(markers -> markers.isActive());
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
}
