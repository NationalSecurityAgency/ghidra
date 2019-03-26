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

import java.awt.Rectangle;
import java.awt.Window;

import org.junit.Test;

import docking.DockingWindowManager;
import generic.util.image.ImageUtils;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;

public class DockingWindowsScreenShots extends GhidraScreenShotGenerator {

	public DockingWindowsScreenShots() {
		super();
	}

	@Test
	public void testCaptureTool() {
		goToListing(0x405a90); // 405a90

		setDividerPercentage(ViewManagerComponentProvider.class, DataTypesProvider.class, .5f);
		setDividerPercentage(ViewManagerComponentProvider.class, CodeViewerProvider.class, .30f);

		captureToolWindow(900, 700);
	}

	@Test
	public void testCaptureWindow_Menu() throws Exception {
		performMemorySearch("85d2");
		performMemorySearch("9000");
		waitForTasks();

		DockingWindowManager mgr = DockingWindowManager.getActiveInstance();
		Window mainWindow = mgr.getMainWindow();
		mainWindow.toFront();
		waitForSwing();

		captureMenuBarMenuHierachy("Window");

		ImageUtils.waitForImage(null, image);
		int width = image.getWidth(null);
		int height = image.getHeight(null);

		// trim the image a bit, it is much wider than it needs to be, as the menu bar is large
		int extra = 300; // this is anecdotal; if this becomes wrong, then we can use the tool's size
		Rectangle newBounds = new Rectangle(0, 0, width - 300, height);
		crop(newBounds);
	}
}
