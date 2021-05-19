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
package ghidra.app.plugin.core.navigation;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiActionDockingAction;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.nav.LocationMemento;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.services.NavigationHistoryService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.base.actions.HorizontalRuleAction;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * <CODE>NextPrevAddressPlugin</CODE> allows the user to go back and forth in
 * the history list and to clear it
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.NAVIGATION,
	shortDescription = "Navigates to previous locations",
	description = "Provides actions for returning to previously visited program locations.",
	servicesRequired = { NavigationHistoryService.class }
)
//@formatter:on
public class NextPrevAddressPlugin extends Plugin {

	private static final String HISTORY_MENU_GROUP = "1_Menu_History_Group";
	private static ImageIcon previousIcon = ResourceManager.loadImage("images/left.png");
	private static ImageIcon nextIcon = ResourceManager.loadImage("images/right.png");

	private static final String PREVIOUS_ACTION_NAME = "Previous Location in History";
	private static final String NEXT_ACTION_NAME = "Next Location in History";
	private static final String PREVIOUS_FUNCTION_ACTION_NAME =
		"Previous Function in History";
	private static final String NEXT_FUNCTION_ACTION_NAME = "Next Function in History";
	private static final String[] CLEAR_MENUPATH = { "Navigation", "Clear History" };

	private NavigationHistoryService historyService;
	private MultiActionDockingAction nextAction;
	private MultiActionDockingAction previousAction;
	private DockingAction nextFunctionAction;
	private DockingAction previousFunctionAction;
	private DockingAction clearAction;
	private BrowserCodeUnitFormat codeUnitFormatter;

	/**
	 * Creates a new instance of the plugin
	 * 
	 * @param tool the tool
	 */
	public NextPrevAddressPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	@Override
	protected void init() {
		historyService = tool.getService(NavigationHistoryService.class);
		codeUnitFormatter = new BrowserCodeUnitFormat(tool);
	}

	MultiActionDockingAction getPreviousAction() {
		return previousAction;
	}

	MultiActionDockingAction getNextAction() {
		return nextAction;
	}

	DockingAction getPreviousFunctionAction() {
		return previousFunctionAction;
	}

	DockingAction getNextFunctionAction() {
		return nextFunctionAction;
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private List<DockingActionIf> getPreviousActions(Navigatable navigatable) {
		Program lastProgram = null;
		List<DockingActionIf> actionList = new ArrayList<>();
		List<LocationMemento> nextLocations = historyService.getPreviousLocations(navigatable);
		for (LocationMemento locationMomento : nextLocations) {
			Program program = locationMomento.getProgram();

			// add an action to signal a change; don't make the first element a separator
			if (program != lastProgram && actionList.size() != 0) {
				// add an action that will trigger a separator to be added to the menu
				actionList.add(createHorizontalRule(lastProgram, program));
			}
			lastProgram = program;
			actionList.add(new NavigationAction(navigatable, locationMomento, false, historyService,
				codeUnitFormatter));
		}
		return actionList;
	}

	private List<DockingActionIf> getNextActions(Navigatable navigatable) {
		Program lastProgram = null;
		List<DockingActionIf> actionList = new ArrayList<>();
		List<LocationMemento> nextLocations = historyService.getNextLocations(navigatable);
		for (LocationMemento locationMomento : nextLocations) {
			Program program = locationMomento.getProgram();

			// add an action to signal a change; don't make the first element a separator
			if (program != lastProgram && !actionList.isEmpty()) {
				// add an action that will trigger a separator to be added to the menu
				actionList.add(createHorizontalRule(lastProgram, program));
			}
			lastProgram = program;

			actionList.add(new NavigationAction(navigatable, locationMomento, true, historyService,
				codeUnitFormatter));
		}
		return actionList;
	}

	private DockingActionIf createHorizontalRule(Program previousProgram, Program nextProgram) {

		DomainFile previousDomainFile = previousProgram.getDomainFile();
		String topName = previousDomainFile.getName();
		DomainFile nextDomainFile = nextProgram.getDomainFile();
		String bottomName = nextDomainFile.getName();
		return new HorizontalRuleAction(getName(), topName, bottomName);
	}

	/**
	 * Creates this plugin's actions.
	 */
	private void createActions() {
		nextAction = new NextPreviousAction(NEXT_ACTION_NAME, getName(), true);
		previousAction = new NextPreviousAction(PREVIOUS_ACTION_NAME, getName(), false);
		nextFunctionAction =
			new NextPreviousFunctionAction(NEXT_FUNCTION_ACTION_NAME, getName(), true);
		previousFunctionAction =
			new NextPreviousFunctionAction(PREVIOUS_FUNCTION_ACTION_NAME, getName(), false);

		clearAction = new DockingAction("Clear History Buffer", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				historyService.clear(getNavigatable(context));
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				if (!(context instanceof ProgramActionContext)) {
					return false;
				}

				Navigatable navigatable = getNavigatable(context);
				boolean hasNext = historyService.hasNext(navigatable);
				boolean hasPrevious = historyService.hasPrevious(navigatable);
				return hasNext || hasPrevious;
			}
		};
		clearAction.addToWindowWhen(NavigatableActionContext.class);
		clearAction.setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, clearAction.getName()));
		MenuData menuData = new MenuData(CLEAR_MENUPATH, HISTORY_MENU_GROUP);
		menuData.setMenuSubGroup("1"); // first in menu!
		clearAction.setMenuBarData(menuData);

		tool.addAction(previousAction);
		tool.addAction(nextAction);
		tool.addAction(previousFunctionAction);
		tool.addAction(nextFunctionAction);
		tool.addAction(clearAction);
	}

	private static String truncateAsNecessary(String value) {
		int maxNameLength = 25; // I know, magic number...
		if (value.length() > maxNameLength) {
			value = value.substring(0, maxNameLength - 2) + "...";
		}
		return value;
	}

	private static String buildActionName(LocationMemento location, CodeUnitFormat formatter) {
		Program program = location.getProgram();
		Address address = location.getProgramLocation().getAddress();

		// Display Format: "Address\t(FunctionName+Offset)\tLabel|Instruction"
		// where each tab character is a delimiter to separate columns
		StringBuilder buffy = new StringBuilder();
		buffy.append(address.toString()).append('\t');

		// in a function?
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(address);
		if (function != null) {
			Address entryPointAddress = function.getEntryPoint();
			String offset = null;
			if (!entryPointAddress.equals(address)) {
				offset = Long.toHexString(address.subtract(entryPointAddress));
			}

			buffy.append('(').append(truncateAsNecessary(function.getName()));
			if (offset != null) {
				buffy.append("+0x").append(offset);
			}
			buffy.append(')');
		}
		buffy.append('\t');

		// label or instruction?
		String representation = getAddressRepresentation(program, address, formatter);
		if (representation != null) {
			buffy.append(representation);
		}

		// use tabs here so that the DockingMenuItemUI used elsewhere in rendering will display
		// the content in tabular form
		return buffy.toString();
	}

	private static String getAddressRepresentation(Program program, Address address,
			CodeUnitFormat formatter) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		if (symbol != null) { // try label first
			return truncateAsNecessary(symbol.getName());
		}

		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(address);
		if (codeUnit == null) {
			return null;
		}
		String displayString = formatter.getRepresentationString(codeUnit);
		if (displayString != null) {
			return truncateAsNecessary(displayString);
		}
		return null;
	}

	private Navigatable getNavigatable(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			Navigatable navigatable = ((NavigatableActionContext) context).getNavigatable();
			if (!navigatable.isConnected()) {
				return navigatable;
			}
		}
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			return service.getDefaultNavigatable();
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NextPreviousAction extends MultiActionDockingAction {

		private final boolean isNext;

		NextPreviousAction(String name, String owner, boolean isNext) {
			super(name, owner);
			this.isNext = isNext;

			setToolBarData(new ToolBarData(isNext ? nextIcon : previousIcon,
				ToolConstants.TOOLBAR_GROUP_TWO));
			setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, name));
			int keycode = isNext ? KeyEvent.VK_RIGHT : KeyEvent.VK_LEFT;
			setKeyBindingData(new KeyBindingData(keycode, InputEvent.ALT_DOWN_MASK));
			setDescription(isNext ? "Go to next location" : "Go to previous location");
			addToWindowWhen(NavigatableActionContext.class);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Navigatable navigatable = getNavigatable(context);
			if (navigatable == null) {
				return false;
			}
			if (isNext) {
				return historyService.hasNext(navigatable);
			}
			return historyService.hasPrevious(navigatable);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Navigatable navigatable = getNavigatable(context);
			if (isNext) {
				historyService.next(navigatable);
			}
			else {
				historyService.previous(navigatable);
			}
		}

		@Override
		public List<DockingActionIf> getActionList(ActionContext context) {
			Navigatable navigatable = getNavigatable(context);
			if (isNext) {
				return getNextActions(navigatable);
			}
			return getPreviousActions(navigatable);
		}

	}

	private static int idCount = 0;

	private class NavigationAction extends DockingAction {
		private final LocationMemento location;
		private final Navigatable navigatable;
		private final NavigationHistoryService service;
		private final boolean isNext;

		private NavigationAction(Navigatable navigatable, LocationMemento location, boolean isNext,
				NavigationHistoryService service, CodeUnitFormat formatter) {
			super("NavigationAction: " + ++idCount, NextPrevAddressPlugin.this.getName());
			this.location = location;
			this.isNext = isNext;
			this.service = service;
			this.navigatable = navigatable;

			Icon navIcon = navigatable.getNavigatableIcon();
			setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, "Navigation_History"));
			setMenuBarData(
				new MenuData(new String[] { buildActionName(location, formatter) }, navIcon));
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isNext) {
				service.next(navigatable, location);
			}
			else {
				service.previous(navigatable, location);
			}
		}
	}

	private class NextPreviousFunctionAction extends DockingAction {

		private final boolean isNext;

		NextPreviousFunctionAction(String name, String owner, boolean isNext) {
			super(name, owner);
			this.isNext = isNext;

			setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, name));
			int keycode = isNext ? KeyEvent.VK_RIGHT : KeyEvent.VK_LEFT;
			setKeyBindingData(
				new KeyBindingData(keycode, InputEvent.ALT_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
			setDescription(
				isNext ? "Go to next function location" : "Go to previous function location");

			String menuItemName = isNext ? "Next History Function" : "Previous History Function";
			MenuData menuData =
				new MenuData(new String[] { "Navigation", menuItemName }, HISTORY_MENU_GROUP);
			menuData.setMenuSubGroup("2"); // after clear
			setMenuBarData(menuData);
			addToWindowWhen(NavigatableActionContext.class);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Navigatable navigatable = getNavigatable(context);
			if (navigatable == null) {
				return false;
			}
			if (isNext) {
				return historyService.hasNextFunction(navigatable);
			}
			return historyService.hasPreviousFunction(navigatable);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Navigatable navigatable = getNavigatable(context);
			if (isNext) {
				historyService.nextFunction(navigatable);
			}
			else {
				historyService.previousFunction(navigatable);
			}
		}
	}

}
