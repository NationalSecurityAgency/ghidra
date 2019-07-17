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
package ghidra.app.plugin.core.colorizer;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import org.jdom.Element;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.navigation.NavigationOptions;
import ghidra.app.services.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.task.SwingUpdateManager;

/**
 * A plugin to provider actions for manipulating the colors of the {@link CodeViewerService}.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Colorizer Plugin",
	description = "Provides actions to set, clear and navigate colors in the Code Browser Listing.",
	servicesProvided = { ColorizingService.class }
)
//@formatter:on
public class ColorizingPlugin extends ProgramPlugin implements DomainObjectListener {

	private static final String MARKER_DESCRIPTION = "Shows the location of user-applied colors";
	private static final int PRIORITY = MarkerService.CHANGE_PRIORITY - 1; // lowest priority
	private static final Color MARKER_COLOR = Color.PINK;
	private static final String COLOR_HISTORY_XML_NAME = "COLOR_HISTORY";
	private static final String COLOR_HISTORY_LIST_XML_NAME = "COLOR_HISTORY";

	static final String MARKER_NAME = "Applied Color";

	static final String NAVIGATION_TOOLBAR_GROUP = "Navigation";
	static final String MENU_PULLRIGHT = "Colors";
	static final String POPUP_MENU_GROUP = "ZColors";
	static final String NAVIGATION_TOOLBAR_SUBGROUP = "Colors"; // at the bottom, except for things without a group

	private ColorizingServiceProvider service;
	private MarkerService markerService;
	private MarkerSet markerSet;

	private NavigationOptions navOptions;
	private NextColorRangeAction nextAction;
	private PreviousColorRangeAction previousAction;

	private SwingUpdateManager updateManager = new SwingUpdateManager(1000, new Runnable() {
		@Override
		public void run() {
			doUpdate();
		}
	});

	public ColorizingPlugin(PluginTool tool) {
		super(tool, true, true);

		service = new ColorizingServiceProvider(tool);
		registerServiceProvided(ColorizingService.class, service);

		tool.setMenuGroup(new String[] { MENU_PULLRIGHT }, POPUP_MENU_GROUP);
	}

	@Override
	protected void init() {
		navOptions = new NavigationOptions(tool);
		createActions();
	}

	@SuppressWarnings("unchecked")
	// non-generic xml library warning
	@Override
	public void readConfigState(SaveState saveState) {
		Element xmlElement = saveState.getXmlElement(COLOR_HISTORY_XML_NAME);
		if (xmlElement != null) {
			List<Color> savedColorHistory = new ArrayList<Color>();
			List<Element> colorElements = xmlElement.getChildren("COLOR");
			for (Element element : colorElements) {
				String rgbString = element.getAttributeValue("RGB");
				int rgb = Integer.parseInt(rgbString);
				savedColorHistory.add(new Color(rgb, true));
			}

			service.setColorHistory(savedColorHistory);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		List<Color> colorHistory = service.getColorHistory();
		if (colorHistory != null) {
			Element colorsElement = new Element(COLOR_HISTORY_LIST_XML_NAME);
			for (Color color : colorHistory) {
				Element element = new Element("COLOR");
				element.setAttribute("RGB", Integer.toString(color.getRGB()));
				colorsElement.addContent(element);
			}
			saveState.putXmlElement(COLOR_HISTORY_XML_NAME, colorsElement);
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		service.setProgram(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		service.setProgram(null);
	}

	@Override
	protected void programClosed(Program program) {
		removeMarkerSet(program);
		service.setProgram(null);
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass.equals(MarkerService.class)) {
			markerService = (MarkerService) service;
		}

	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass.equals(MarkerService.class)) {
			markerService = null;
		}
		else if (interfaceClass.equals(GoToService.class)) {
			nextAction.remove();
			previousAction.remove();
		}
	}

	private void createActions() {
		//
		// Color Changing
		//

		String group = "ZClear";
		int subgroup = 1;

		HelpLocation helpLocation = new HelpLocation("CodeBrowserPlugin", "Listing_Background");

		// set color action
		DockingAction setColorAction = new DockingAction("Set Color", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ListingActionContext listingContext = (ListingActionContext) context;

				Color currentColor = service.getBackgroundColor(listingContext.getAddress());
				Color color = service.getColorFromUser(currentColor);
				if (color == null) {
					return;
				}

				Command command = null;
				ProgramSelection selection = listingContext.getSelection();
				if (selection != null && !selection.isEmpty()) {
					command = new SetColorCommand(color, service, selection);
				}
				else {
					Address address = listingContext.getAddress();
					command = new SetColorCommand(color, service, currentProgram, address);
				}

				tool.execute(command, currentProgram);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return false;
				}
				return true;
			}
		};
		setColorAction.setPopupMenuData(new MenuData(new String[] { MENU_PULLRIGHT, "Set Color" },
			null, group, MenuData.NO_MNEMONIC, Integer.toString(subgroup++)));
		setColorAction.setHelpLocation(helpLocation);

		// clear action
		DockingAction clearAction = new DockingAction("Clear Color", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ListingActionContext listingContext = (ListingActionContext) context;
				AddressSetView selection = listingContext.getSelection();
				if (selection == null || selection.isEmpty()) {
					AddressSet set = new AddressSet();
					set.add(listingContext.getAddress());
					selection = set;
				}
				ClearColorCommand command = new ClearColorCommand(service, selection);
				tool.execute(command, currentProgram);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return false;
				}

				ListingActionContext listingContext = (ListingActionContext) context;
				ProgramSelection selection = listingContext.getSelection();
				if (selection != null && !selection.isEmpty()) {
					return isColored(selection);
				}
				return isColored(listingContext.getAddress());
			}
		};
		clearAction.setPopupMenuData(new MenuData(new String[] { MENU_PULLRIGHT, "Clear Color" },
			null, group, MenuData.NO_MNEMONIC, Integer.toString(subgroup++)));
		clearAction.setHelpLocation(helpLocation);

		// clear all action
		DockingAction clearAllAction = new DockingAction("Clear All Colors", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ClearColorCommand command = new ClearColorCommand(service);
				tool.execute(command, currentProgram);
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ListingActionContext)) {
					return false;
				}

				AddressSetView set = service.getAllBackgroundColorAddresses();
				return !set.isEmpty();
			}
		};
		clearAllAction.setPopupMenuData(new MenuData(new String[] { MENU_PULLRIGHT,
			"Clear All Colors" }, null, group, MenuData.NO_MNEMONIC, Integer.toString(subgroup++)));
		clearAllAction.setHelpLocation(helpLocation);

		//
		// Navigation
		//

		// next color range start
		nextAction = new NextColorRangeAction(this, tool, navOptions);

		// previous color range start
		previousAction = new PreviousColorRangeAction(this, tool, navOptions);

		tool.addAction(clearAction);
		tool.addAction(clearAllAction);
		tool.addAction(setColorAction);
		tool.addAction(nextAction);
		tool.addAction(previousAction);
	}

	private boolean isColored(ProgramSelection selection) {
		AddressSetView appliedColorAddresses = service.getAllBackgroundColorAddresses();
		return selection.intersects(appliedColorAddresses);
	}

	private boolean isColored(Address address) {
		Color color = service.getBackgroundColor(address);
		return color != null;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED)) {
			updateManager.update();
		}
	}

	@Override
	protected void dispose() {
		updateManager.dispose();
		navOptions.dispose();
		super.dispose();
	}

	private void removeMarkerSet(Program program) {
		if (markerService != null) {
			if (markerSet != null) {
				markerService.removeMarker(markerSet, program);
			}
		}
	}

	private void doUpdate() {
		AddressSetView set = service.getAllBackgroundColorAddresses();
		updateMarkers(set);
	}

	private void updateMarkers(AddressSetView set) {
		if (markerService == null) {
			return;
		}

		if (markerSet == null) {
			// TODO: should we instead pick a reasonable color??
			Address minAddress = set.getMinAddress();
			Color color = service.getBackgroundColor(minAddress);
			if (color == null) {
				// not sure if this can happen
				color = MARKER_COLOR;
			}

			markerSet =
				markerService.createPointMarker(MARKER_NAME, MARKER_DESCRIPTION, currentProgram,
					PRIORITY, false, true, false, color, null);
		}
		else {
			markerSet.clearAll();
		}

		AddressRangeIterator iterator = set.getAddressRanges();
		while (iterator.hasNext()) {
			AddressRange range = iterator.next();
			markerSet.add(range);
		}
	}

	ColorizingService getColorizingService() {
		return service;
	}

	GoToService getGoToService() {
		return tool.getService(GoToService.class);
	}
}
