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

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.tool.ToolConstants;
import docking.widgets.EventTrigger;
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.services.GoToService;
import ghidra.app.services.MarkerSet;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class NextPreviousMarkerAction extends MultiStateDockingAction<String> {
	//private static final ImageIcon  new ImageIcon(); = null;
	private boolean isForward = true;
	private PluginTool tool;

	private static ImageIcon markerIcon = ResourceManager.loadImage("images/M.gif");
	private static ImageIcon markerAnalysisBookmarkIcon = ResourceManager.loadImage("images/M.gif");
	private static ImageIcon markerConflictingChangesIcon =
		ResourceManager.loadImage("images/edit-delete.png");
	private static ImageIcon markerLatestVersionChangesIcon =
		ResourceManager.loadImage("images/information.png");
	private static ImageIcon markerNotCheckedInChangesIcon =
		ResourceManager.loadImage("images/notes.gif");
	private static ImageIcon markerUnSavedChangesIcon =
		ResourceManager.loadImage("images/warning.png");
	private static ImageIcon markerCursorIcon = ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerErrorBookmarkIcon =
		ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerHighlightIcon = ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerInfoBookmarkIcon =
		ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerNoteBookmarkIcon =
		ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerSelectionIcon = ResourceManager.loadImage("images/unknown.gif");
	private static ImageIcon markerWarningBookmarkIcon =
		ResourceManager.loadImage("images/unknown.gif");

	public NextPreviousMarkerAction(PluginTool tool, String owner, String subGroup) {
		super("Next Marker", owner);
		this.tool = tool;

		ToolBarData toolBarData =
			new ToolBarData(markerIcon, ToolConstants.TOOLBAR_GROUP_FOUR);
		toolBarData.setToolBarSubGroup(subGroup);
		setToolBarData(toolBarData);

		MenuData menuData =
			new MenuData(new String[] { ToolConstants.MENU_NAVIGATION, getMenuName() }, markerIcon,
				ToolConstants.MENU_GROUP_NEXT_CODE_UNIT_NAV);
		menuData.setMenuSubGroup(subGroup);
		setMenuBarData(menuData);

		setKeyBindingData(new KeyBindingData(getKeyStroke()));
		addToWindowWhen(CodeViewerActionContext.class);

		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, getName()));
		setDescription("Set marker options");
		addToWindowWhen(CodeViewerActionContext.class);

		ActionState<String> allMarkers =
			new ActionState<String>("All Types", markerIcon, "All Types");
		ActionState<String> analysis =
			new ActionState<String>("Analysis Marker", markerAnalysisBookmarkIcon,
				BookmarkType.ANALYSIS);
		ActionState<String> conflictingChanges =
			new ActionState<String>("Conflicting Changes", markerAnalysisBookmarkIcon,
				"Conflicting Changes");
		ActionState<String> latestVersionChanges =
			new ActionState<String>("Latest Version Changes", markerAnalysisBookmarkIcon,
				"Latest Version Changes");
		ActionState<String> notCheckedInChanges =
			new ActionState<String>("Not Checked In Changes", markerAnalysisBookmarkIcon,
				"Not Checked In Changes");
		ActionState<String> unsavedChanges =
			new ActionState<String>("Unsaved Changes", markerIcon, "Unsaved Changes");
		ActionState<String> cursor = new ActionState<String>("Cursor", markerIcon, "Cursor");
		ActionState<String> error =
			new ActionState<String>("Error Marker", markerIcon, BookmarkType.ERROR);
		ActionState<String> highlight =
			new ActionState<String>("Highlight", markerIcon, "Highlight");
		ActionState<String> info =
			new ActionState<String>("Info Marker", markerIcon, BookmarkType.INFO);
		ActionState<String> note =
			new ActionState<String>("Note Marker", markerIcon, BookmarkType.NOTE);
		ActionState<String> selection =
			new ActionState<String>("Selection", markerIcon, "Selection");
		ActionState<String> warning =
			new ActionState<String>("Warning Marker", markerIcon, BookmarkType.WARNING);
		ActionState<String> custom =
			new ActionState<String>("Custom Marker", markerIcon, "Custom Marker");

		addActionState(allMarkers);
		addActionState(analysis);
		addActionState(conflictingChanges);
		addActionState(latestVersionChanges);
		addActionState(notCheckedInChanges);
		addActionState(unsavedChanges);
		addActionState(cursor);
		addActionState(error);
		addActionState(highlight);
		addActionState(info);
		addActionState(note);
		addActionState(selection);
		addActionState(warning);
		addActionState(custom);

		setCurrentActionState(allMarkers); // default
	}

	@Override
	public void setMenuBarData(MenuData newMenuData) {
		//
		// When we are in the menu we will display our default icon, which is the marker icon.
		//
		superSetMenuBarData(newMenuData);
	}

	@Override
	protected void doActionPerformed(ActionContext context) {
		gotoNextPrevious((ListingActionContext) context.getContextObject(),
			this.getCurrentUserData());
	}

	@Override
	public void actionStateChanged(ActionState<String> newActionState, EventTrigger trigger) {
		// nothing
	}

	// Find the beginning of the next instruction range
	/*private Address getNextAddress(Program program, Address address, String markerType) {
		MarkerSet nextMarker = getNextMarker(program, address, true, markerType);
		return nextMarker == null ? null : nextMarker.getAddressSet().getMinAddress();
	}
	*/
	/*private Address getPreviousAddress(Program program, Address address, String markerType) {
		MarkerManager markerManager = program.getMarkerManager();
		Iterator<Marker> markerIterator = markerManager.getMarkersIterator(address, false);
		if (isMarkerAddressEqualToCurrent(markerIterator.next(), address)) {
	
		}
		MarkerSet nextMarker = getNextMarker(program, address, false, markerType);
		return nextMarker == null ? null : nextMarker.getAddressSet().getMinAddress();
	}
	
	private MarkerSet getNextMarker(Program program, Address address, boolean forward,
			String markerType) {
		MarkerManager markerManager = program.getMarkerManager();
		Iterator<MarkerSet> markerIterator = markerManager.getMarkersIterator(address, forward);
		while (markerIterator.hasNext()) {
			MarkerSet nextMarker = markerIterator.next();
			Address nextAddress = nextMarker.getAddressSet().getMinAddress();
			if (nextAddress.isExternalAddress()) {
				continue;
			}
	
			if (markerType.equals(MarkerType.ALL_TYPES) && !nextAddress.equals(address)) {
				return nextMarker;
			}
			else if (markerType.equals("Custom")) {
				if (!nextMarker.getTypeString().equals(MarkerType.ANALYSIS) &&
					!nextMarker.getTypeString().equals(MarkerType.INFO) &&
					!nextMarker.getTypeString().equals(MarkerType.NOTE) &&
					!nextMarker.getTypeString().equals(MarkerType.WARNING) &&
					!nextMarker.getTypeString().equals(MarkerType.ERROR) &&
					!nextAddress.equals(address)) {
					return nextMarker;
				}
	
			}
			else if (nextMarker.getTypeString().equals(markerType) && !nextAddress.equals(address)) {
				return nextMarker;
			}
		}
	
		if (!markerIterator.hasNext()) {
			return null;
		}
		return markerIterator.next();
	}
	*/
	@SuppressWarnings("unused")
	private boolean isMarkerAddressEqualToCurrent(MarkerSet marker, Address address) {
		if (marker == null) {
			return false;
		}
		return !address.equals(marker.getMinAddress());
	}

	private void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		service.goTo(navigatable, address);
	}

//==================================================================================================
// AbstractNextPreviousAction Methods
//==================================================================================================
	void gotoNextPrevious(final ListingActionContext context, final String markerType) {
		/*final Address address =
			isForward ? getNextAddress(context.getProgram(), context.getAddress(), markerType)
					: getPreviousAddress(context.getProgram(), context.getAddress(), markerType);
		*//*
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						gotoAddress(context, address);
					}
				});*/
	}

	private void gotoAddress(ListingActionContext listingActionContext, Address address) {
		if (address == null) {
			tool.setStatusInfo("Unable to locate another " + getNavigationTypeName() +
				" past the current range, in the current direction.");
			return;
		}
		tool.clearStatusInfo();
		GoToService service = tool.getService(GoToService.class);
		if (service != null) {
			Navigatable navigatable = listingActionContext.getNavigatable();
			gotoAddress(service, navigatable, address);
		}

	}

	public void setDirection(boolean isForward) {
		this.isForward = isForward;
		getMenuBarData().setMenuItemName(getMenuName());
		setDescription(getDescription());
	}

	private String getMenuName() {
		String prefix = isForward ? "Next " : "Previous ";
		return prefix + getNavigationTypeName();
	}

	private String getNavigationTypeName() {
		return "Marker";
	}

	private KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK |
			InputEvent.ALT_DOWN_MASK);
	}

//==================================================================================================
// CodeViewerContextAction Methods
//==================================================================================================	
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isEnabledForContext((CodeViewerActionContext) context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isValidContext((CodeViewerActionContext) context);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isAddToPopup((CodeViewerActionContext) context);
	}

	protected boolean isValidContext(CodeViewerActionContext context) {
		return true;
	}

	protected boolean isEnabledForContext(CodeViewerActionContext context) {
		return true;
	}

	protected boolean isAddToPopup(CodeViewerActionContext context) {
		return isEnabledForContext(context);
	}

}
