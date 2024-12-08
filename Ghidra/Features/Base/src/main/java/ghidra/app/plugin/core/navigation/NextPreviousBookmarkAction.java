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

import java.awt.event.*;
import java.util.Iterator;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.tool.ToolConstants;
import docking.widgets.EventTrigger;
import generic.theme.GIcon;
import generic.util.image.ImageUtils;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import resources.*;

public class NextPreviousBookmarkAction extends MultiStateDockingAction<String> {

	public static final String ALL_BOOKMARK_TYPES = "All Bookmark Types";

	private static final Icon INVERTED_OVERLAY_ICON =
		ImageUtils.makeTransparent(Icons.NOT_ALLOWED_ICON, .5f);

	private PluginTool tool;
	private boolean isForward = true;
	private boolean isInverted;

	//@formatter:off
	private static final Icon BOOKMARK_ICON = new GIcon("icon.plugin.navigation.bookmark");
	private static final Icon BOOKMARK_ANALYSIS_ICON = new GIcon("icon.plugin.navigation.bookmark.analysis");
	private static final Icon BOOKMARK_ERROR_ICON = new GIcon("icon.plugin.navigation.bookmark.error");
	private static final Icon BOOKMARK_INFO_ICON = new GIcon("icon.plugin.navigation.bookmark.info");
	private static final Icon BOOKMARK_NOTE_ICON = new GIcon("icon.plugin.navigation.bookmark.note");
	private static final Icon BOOKMARK_WARNING_ICON = new GIcon("icon.plugin.navigation.bookmark.warning");
	private static final Icon BOOKMARK_UNKNOWN_ICON = new GIcon("icon.plugin.navigation.bookmark.unknown");
	//@formatter:on

	public NextPreviousBookmarkAction(PluginTool tool, String owner, String subGroup) {
		super("Next Bookmark", owner);
		this.tool = tool;
		setContextClass(NavigatableActionContext.class, true);

		ToolBarData toolBarData =
			new ToolBarData(BOOKMARK_ICON, ToolConstants.TOOLBAR_GROUP_FOUR);
		toolBarData.setToolBarSubGroup(subGroup);
		setToolBarData(toolBarData);

		addToWindowWhen(CodeViewerActionContext.class);
		setKeyBindingData(new KeyBindingData(getKeyStroke()));

		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, getName()));
		setDescription("Set bookmark options");

		ActionState<String> allBookmarks =
			new ActionState<>("All Types", BOOKMARK_ICON, ALL_BOOKMARK_TYPES);
		ActionState<String> analysis =
			new ActionState<>("Analysis", BOOKMARK_ANALYSIS_ICON, BookmarkType.ANALYSIS);
		ActionState<String> error =
			new ActionState<>("Error", BOOKMARK_ERROR_ICON, BookmarkType.ERROR);
		ActionState<String> info = new ActionState<>("Info", BOOKMARK_INFO_ICON, BookmarkType.INFO);
		ActionState<String> note = new ActionState<>("Note", BOOKMARK_NOTE_ICON, BookmarkType.NOTE);
		ActionState<String> warning =
			new ActionState<>("Warning", BOOKMARK_WARNING_ICON, BookmarkType.WARNING);
		ActionState<String> custom = new ActionState<>("Custom", BOOKMARK_UNKNOWN_ICON, "Custom");

		addActionState(allBookmarks);
		addActionState(analysis);
		addActionState(error);
		addActionState(info);
		addActionState(note);
		addActionState(warning);
		addActionState(custom);

		setCurrentActionState(allBookmarks); // default
	}

	@Override
	public void setMenuBarData(MenuData newMenuData) {
		//
		// When we are in the menu we will display our default icon, which is the bookmark icon.
		//
		superSetMenuBarData(newMenuData);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			gotoNextPrevious((NavigatableActionContext) context, this.getCurrentUserData());
		}
	}

	@Override
	public void actionStateChanged(ActionState<String> newActionState, EventTrigger trigger) {

		Icon icon = newActionState.getIcon();
		ToolBarData tbData = getToolBarData();
		tbData.setIcon(isInverted ? invertIcon(icon) : icon);
	}

	private Address getNextAddress(Program program, Address address, String bookmarkType) {

		if (isInverted) {
			return getNextAddressOfNonBookmark(program, address, bookmarkType);
		}

		return getAddressOfNextBookmarkAfter(program, address, bookmarkType);
	}

	private Address getPreviousAddress(Program program, Address address, String bookmarkType) {

		if (isInverted) {
			return getPreviousAddressOfNonBookmark(program, address, bookmarkType);
		}

		return getAddressOfPreviousBookmarkBefore(program, address, bookmarkType);
	}

	private Address getNextAddressOfNonBookmark(Program program, Address address,
			String bookmarkType) {

		if (ALL_BOOKMARK_TYPES.equals(bookmarkType)) {
			// special case:  when 'all types' is negated, then we skip runs of non-bookmarks to
			//                allow users to quickly jump to areas with any bookmarks
			address = getAddressOfNextBookmarkAfter(program, address, bookmarkType);
		}

		return getAdddressOfNextPreviousNonBookmark(program, address, bookmarkType, true);
	}

	private Address getPreviousAddressOfNonBookmark(Program program, Address address,
			String bookmarkType) {

		if (ALL_BOOKMARK_TYPES.equals(bookmarkType)) {
			// special case:  when 'all types' is negated, then we skip runs of non-bookmarks to
			//                allow users to quickly jump to areas with any bookmarks
			address = getAddressOfPreviousBookmarkBefore(program, address, bookmarkType);
		}

		return getAdddressOfNextPreviousNonBookmark(program, address, bookmarkType, false);
	}

	private Address getAdddressOfNextPreviousNonBookmark(Program program, Address address,
			String bookmarkType, boolean forward) {

		if (address == null) {
			return null;
		}

		address = forward ? address.next() : address.previous();
		if (address == null) {
			return null;
		}

		//
		// By default, if we are given a specific bookmark type, then we need only to find the
		// next bookmark of a different type.  However, if the given type is 'all bookmarks', then
		// do something reasonable, which is to find the next code unit without a bookmark.  Users
		// are not likely to use this option.
		//
		if (bookmarkType.equals(ALL_BOOKMARK_TYPES)) {
			return getNextPreviousCuWithoutBookmarkAddress(program, address, forward);
		}

		BookmarkManager bm = program.getBookmarkManager();
		Iterator<Bookmark> it = bm.getBookmarksIterator(address, forward);
		while (it.hasNext()) {
			Bookmark nextBookmark = it.next();
			Address nextAddress = nextBookmark.getAddress();
			if (nextAddress.isExternalAddress()) {
				continue;
			}

			if (!nextBookmark.getTypeString().equals(bookmarkType)) {
				return nextBookmark.getAddress();
			}

		}
		return null;
	}

	private Address getNextPreviousCuWithoutBookmarkAddress(Program program, Address address,
			boolean forward) {

		CodeUnitIterator it = program.getListing().getCodeUnits(address, forward);
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			Address minAddress = cu.getMinAddress();
			BookmarkManager bm = program.getBookmarkManager();
			Bookmark[] bookmarks = bm.getBookmarks(minAddress);
			if (bookmarks.length == 0) {
				return minAddress;
			}
		}

		return null;
	}

	private Address getAddressOfNextBookmarkAfter(Program program, Address address,
			String bookmarkType) {
		Address start = getNextAddressToBeginSearchingForward(program, address);
		Bookmark nextBookmark = getNextPreviousBookmark(program, start, true, bookmarkType);
		return nextBookmark == null ? null : nextBookmark.getAddress();

	}

	private Address getAddressOfPreviousBookmarkBefore(Program program, Address address,
			String bookmarkType) {
		Address start = getNextAddressToBeginSearchingBackward(program, address);
		Bookmark nextBookmark = getNextPreviousBookmark(program, start, false, bookmarkType);
		return nextBookmark == null ? null : nextBookmark.getAddress();
	}

	private Address getNextAddressToBeginSearchingForward(Program program, Address address) {
		CodeUnit cu = getMostPrimitiveCodeUnitContaining(program, address);
		return cu == null ? address : cu.getMaxAddress().next();
	}

	private Address getNextAddressToBeginSearchingBackward(Program program, Address address) {
		CodeUnit cu = getMostPrimitiveCodeUnitContaining(program, address);
		return cu == null ? address : cu.getMinAddress().previous();
	}

	private CodeUnit getMostPrimitiveCodeUnitContaining(Program program, Address address) {
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}

		if (cu instanceof Data) {
			Data data = (Data) cu;
			cu = data.getPrimitiveAt((int) address.subtract(data.getAddress()));
		}

		return cu;
	}

	private Bookmark getNextPreviousBookmark(Program program, Address address, boolean forward,
			String bookmarkType) {

		BookmarkManager bm = program.getBookmarkManager();
		Iterator<Bookmark> it = bm.getBookmarksIterator(address, forward);
		while (it.hasNext()) {
			Bookmark nextBookmark = it.next();
			Address nextAddress = nextBookmark.getAddress();
			if (nextAddress.isExternalAddress()) {
				continue;
			}

			if (bookmarkType.equals(ALL_BOOKMARK_TYPES)) {
				return nextBookmark;
			}
			else if (bookmarkType.equals("Custom") &&
				isNotBuiltInType(address, nextBookmark, nextAddress)) {
				return nextBookmark;
			}
			else if (nextBookmark.getTypeString().equals(bookmarkType)) {
				return nextBookmark;
			}

		}

		return null;
	}

	private boolean isNotBuiltInType(Address address, Bookmark nextBookmark, Address nextAddress) {
		return !nextBookmark.getTypeString().equals(BookmarkType.ANALYSIS) &&
			!nextBookmark.getTypeString().equals(BookmarkType.INFO) &&
			!nextBookmark.getTypeString().equals(BookmarkType.NOTE) &&
			!nextBookmark.getTypeString().equals(BookmarkType.WARNING) &&
			!nextBookmark.getTypeString().equals(BookmarkType.ERROR) &&
			!nextAddress.equals(address);
	}

	private void gotoAddress(GoToService service, Navigatable navigatable, Address address) {
		service.goTo(navigatable, address);
	}

//==================================================================================================
// AbstractNextPreviousAction Methods
//==================================================================================================
	private void gotoNextPrevious(final NavigatableActionContext context,
			final String bookmarkType) {
		boolean direction = isForward;
		if (context.hasAnyEventClickModifiers(ActionEvent.SHIFT_MASK)) {
			direction = !direction;
		}

		Address address = direction
				? getNextAddress(context.getProgram(), context.getAddress(), bookmarkType)
				: getPreviousAddress(context.getProgram(), context.getAddress(), bookmarkType);

		Swing.runLater(() -> gotoAddress(context, address));
	}

	private void gotoAddress(NavigatableActionContext listingActionContext, Address address) {
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
		setDescription(getToolTipText());
	}

	public void setInverted(boolean isInverted) {
		this.isInverted = isInverted;

		ActionState<String> state = getCurrentState();
		Icon icon = state.getIcon();
		getToolBarData().setIcon(isInverted ? invertIcon(icon) : icon);
		setDescription(getToolTipText());
	}

	private Icon invertIcon(Icon icon) {
		MultiIconBuilder builder = new MultiIconBuilder(icon);
		builder.addIcon(INVERTED_OVERLAY_ICON, 10, 10, QUADRANT.LR);
		return builder.build();
	}

	@Override
	public String getToolTipText() {
		String description = "Go To " + (isForward ? "Next" : "Previous");
		if (isInverted) {
			description += " Non-Bookmark: ";
		}
		else {
			description += " Bookmark: ";
		}
		description += getCurrentState().getName();
		description += " (shift-click inverts direction)";
		return description;
	}

	private String getNavigationTypeName() {
		return "Bookmark";
	}

	private KeyStroke getKeyStroke() {
		return KeyStroke.getKeyStroke(KeyEvent.VK_B,
			InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK);
	}

//==================================================================================================
// CodeViewerContextAction Methods
//==================================================================================================
	@Override
	public boolean isValidContext(ActionContext context) {
		return context instanceof ListingActionContext;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context instanceof ListingActionContext;
	}
}
