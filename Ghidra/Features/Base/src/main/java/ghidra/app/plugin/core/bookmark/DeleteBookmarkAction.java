/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.bookmark;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.util.MarkerLocation;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

/**
 * <CODE>DeleteFunctionAction</CODE> allows the user to delete a function at
 * the entry point of the function.
 */
class DeleteBookmarkAction extends DockingAction {
	/** the plugin associated with this action. */
	BookmarkPlugin plugin;
	Bookmark bookmark;
	Address popupLocation;

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param id the name for this action.
	 * @param plugin the plugin this action is associated with.
	 */
	DeleteBookmarkAction(BookmarkPlugin plugin, Bookmark bookmark, boolean isOffcut) {
		super("Delete " + bookmark.getTypeString() + " Bookmark", plugin.getName(), false);
		this.plugin = plugin;
		this.bookmark = bookmark;

		setDescription("Delete " + bookmark.getTypeString() + " bookmark.");
		String name = bookmark.getTypeString();
		String comment = bookmark.getComment();
		if (comment != null && comment.length() != 0) {
			name += ": " + comment;
		}
		if (isOffcut) {
			name = "(@" + bookmark.getAddress() + ") " + name;
		}
		setPopupMenuData(new MenuData(new String[] { "Delete Bookmark", name }, "Bookmark"));
		setHelpLocation(new HelpLocation("BookmarkPlugin", "Delete_Bookmark"));

//		if (BookmarkType.NOTE.equals(bookmark.getTypeString())) {
//			setAcceleratorKey(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0));
//		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return context.getContextObject() instanceof MarkerLocation;
	}

	/**
	 * Method called when the action is invoked.
	 * @param ActionEvent details regarding the invocation of this action
	 */
	@Override
	public void actionPerformed(ActionContext context) {
		if (isEnabled()) {
			plugin.deleteBookmark(bookmark);
		}
	}

}
