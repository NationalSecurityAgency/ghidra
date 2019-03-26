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
package help.screenshot;

import org.junit.Test;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.bookmark.BookmarkProvider;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;

public class BookmarkPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testAddBookmarkDialog() {
		performAction("Add Bookmark", "BookmarkPlugin", false);
		captureDialog();
	}

	@Test
	public void testBefore() {
		removeFlowArrows();
		positionListingTop(0x40f66a);
		addSelection(0x40f66c, 0x40f66f);
		addSelection(0x40f672, 0x40f672);
		addSelection(0x40f676, 0x40f676);

		captureIsolatedProvider(CodeViewerProvider.class, 500, 350);
	}

	@Test
	public void testAfter() {
		removeFlowArrows();
		createBookmarks();
		captureIsolatedProvider(CodeViewerProvider.class, 500, 350);
	}

	@Test
	public void testBookmarks() {
		removeFlowArrows();
		createBookmarks();
		performAction("Show Bookmarks", "BookmarkPlugin", true);
		captureIsolatedProvider(BookmarkProvider.class, 900, 300);

	}

	@Test
	public void testBookmarksFilter() {
		performAction("Show Bookmarks", "BookmarkPlugin", true);
		performAction("Filter Bookmarks", "BookmarkPlugin", false);
		waitForSwing();

		DialogComponentProvider dialog = waitForDialogComponent("Bookmark Filter");
		captureDialog(dialog);
		close(dialog);
		waitForSwing();
	}

	@Test
	public void testMarkerForBookmark() {
		removeFlowArrows();
		closeProvider(DataTypesProvider.class);
		positionListingTop(0x4058ed);
		createBookmark(0x4058fc);
		program.flushEvents();
		captureToolWindow(810, 500);
	}

	private void createBookmarks() {
		positionListingTop(0x40f66a);
		addSelection(0x40f66c, 0x40f66f);
		addSelection(0x40f672, 0x40f672);
		addSelection(0x40f676, 0x40f676);

		performAction("Add Bookmark", "BookmarkPlugin", false);
		pressOkOnDialog();
	}

}
