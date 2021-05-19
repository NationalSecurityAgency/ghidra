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
import java.util.Iterator;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.tool.ToolConstants;
import docking.widgets.EventTrigger;
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
import resources.ResourceManager;

public class NextPreviousBookmarkAction extends MultiStateDockingAction<String> {
	private boolean isForward = true;
	private PluginTool tool;

	private static ImageIcon bookmarkIcon = ResourceManager.loadImage("images/B.gif");
	private static ImageIcon bookmarkAnalysisIcon =
		ResourceManager.loadImage("images/applications-system.png");
	private static ImageIcon bookmarkErrorIcon =
		ResourceManager.loadImage("images/edit-delete.png");
	private static ImageIcon bookmarkInfoIcon = ResourceManager.loadImage("images/information.png");
	private static ImageIcon bookmarkNoteIcon = ResourceManager.loadImage("images/notes.gif");
	private static ImageIcon bookmarkWarningIcon = ResourceManager.loadImage("images/warning.png");
	private static ImageIcon bookmarkUnknownIcon = ResourceManager.loadImage("images/unknown.gif");

	public NextPreviousBookmarkAction(PluginTool tool, String owner, String subGroup) {
		super("Next Bookmark", owner);
		this.tool = tool;
		setSupportsDefaultToolContext(true);

		ToolBarData toolBarData =
			new ToolBarData(bookmarkIcon, ToolConstants.TOOLBAR_GROUP_FOUR);
		toolBarData.setToolBarSubGroup(subGroup);
		setToolBarData(toolBarData);

		addToWindowWhen(CodeViewerActionContext.class);
		setKeyBindingData(new KeyBindingData(getKeyStroke()));

		setHelpLocation(new HelpLocation(HelpTopics.NAVIGATION, getName()));
		setDescription("Set bookmark options");

		ActionState<String> allBookmarks =
			new ActionState<>("All Types", bookmarkIcon, BookmarkType.ALL_TYPES);
		ActionState<String> analysis =
			new ActionState<>("Analysis", bookmarkAnalysisIcon, BookmarkType.ANALYSIS);
		ActionState<String> error =
			new ActionState<>("Error", bookmarkErrorIcon, BookmarkType.ERROR);
		ActionState<String> info = new ActionState<>("Info", bookmarkInfoIcon, BookmarkType.INFO);
		ActionState<String> note = new ActionState<>("Note", bookmarkNoteIcon, BookmarkType.NOTE);
		ActionState<String> warning =
			new ActionState<>("Warning", bookmarkWarningIcon, BookmarkType.WARNING);
		ActionState<String> custom = new ActionState<>("Custom", bookmarkUnknownIcon, "Custom");

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
	protected void doActionPerformed(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			gotoNextPrevious((NavigatableActionContext) context, this.getCurrentUserData());
		}
	}

	@Override
	public void actionStateChanged(ActionState<String> newActionState, EventTrigger trigger) {
		// nothing
	}

	// Find the beginning of the next instruction range
	private Address getNextAddress(Program program, Address address, String bookmarkType) {
		Address start = getNextAddressToBeginSearchingForward(program, address);
		Bookmark nextBookmark = getNextBookmark(program, start, true, bookmarkType);
		return nextBookmark == null ? null : nextBookmark.getAddress();
	}

	private Address getPreviousAddress(Program program, Address address, String bookmarkType) {
		Address start = getNextAddressToBeginSearchingBackward(program, address);
		Bookmark nextBookmark = getNextBookmark(program, start, false, bookmarkType);
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

	private Bookmark getNextBookmark(Program program, Address address, boolean forward,
			String bookmarkType) {
		BookmarkManager bookmarkManager = program.getBookmarkManager();
		Iterator<Bookmark> bookmarkIterator =
			bookmarkManager.getBookmarksIterator(address, forward);
		while (bookmarkIterator.hasNext()) {
			Bookmark nextBookmark = bookmarkIterator.next();
			Address nextAddress = nextBookmark.getAddress();
			if (nextAddress.isExternalAddress()) {
				continue;
			}

			if (bookmarkType.equals(BookmarkType.ALL_TYPES)) {
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

		if (!bookmarkIterator.hasNext()) {
			return null;
		}
		return bookmarkIterator.next();
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
		final Address address =
			isForward ? getNextAddress(context.getProgram(), context.getAddress(), bookmarkType)
					: getPreviousAddress(context.getProgram(), context.getAddress(), bookmarkType);

		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				gotoAddress(context, address);
			}
		});
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

	@Override
	public String getToolTipText() {
		String description = "Go To " + (isForward ? "Next" : "Previous");
		description += " Bookmark: " + getCurrentState().getName();
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
