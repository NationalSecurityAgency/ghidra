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
package docking;

import static org.junit.Assert.*;

import java.awt.*;

import javax.swing.*;

import org.junit.*;

import docking.test.AbstractDockingTest;
import generic.test.TestUtils;

/**
 * Tests which window becomes the parent of a dialog when Java reports no active window.  Java's
 * active window is controlled by a focus manager installed by this test, and the tool's last
 * active window is set directly, so that the tests do not depend on the OS window focus.
 */
public class DialogParentFallbackTest extends AbstractDockingTest {

	private FakeDockingTool tool;
	private Window fakeActiveWindow;

	@Before
	public void setUp() {
		tool = new FakeDockingTool();
		runSwing(() -> tool.setVisible(true));
		waitForSwing();
	}

	@After
	public void tearDown() {
		closeAllWindows();
	}

	@Test
	public void testNoActiveWindow_UsesLastActiveWindow() {
		Window detachedWindow = showDetachedProvider(true);
		setLastActiveWindow(detachedWindow);
		fakeActiveWindow = null;

		Window owner = showDialogAndGetOwner();
		assertSame(detachedWindow, owner);
	}

	@Test
	public void testNoActiveWindow_LastActiveIsClosedModalDialog_UsesItsOwner() {
		Window detachedWindow = showDetachedProvider(true);
		JDialog closedDialog = runSwing(() -> new JDialog(detachedWindow, "Closed Dialog",
			Dialog.ModalityType.APPLICATION_MODAL));
		setLastActiveWindow(closedDialog);
		fakeActiveWindow = null;

		Window owner = showDialogAndGetOwner();
		assertSame(detachedWindow, owner);
	}

	@Test
	public void testNoActiveWindow_NoLastActiveWindow_UsesToolFrame() {
		setLastActiveWindow(null);
		fakeActiveWindow = null;

		Window owner = showDialogAndGetOwner();
		assertSame(tool.getToolFrame(), owner);
	}

	@Test
	public void testActiveWindow_PreferredOverLastActiveWindow() {
		Window detachedWindow = showDetachedProvider(true);
		setLastActiveWindow(detachedWindow);
		fakeActiveWindow = tool.getToolFrame();

		Window owner = showDialogAndGetOwner();
		assertSame(tool.getToolFrame(), owner);
	}

	@Test
	public void testNoActiveWindow_LastActiveWindowCannotBeParent_UsesToolFrame() {
		Window detachedWindow = showDetachedProvider(false);
		setLastActiveWindow(detachedWindow);
		fakeActiveWindow = null;

		Window owner = showDialogAndGetOwner();
		assertSame(tool.getToolFrame(), owner);
	}

	private Window showDetachedProvider(boolean canBeParent) {
		DetachedProvider provider = new DetachedProvider(canBeParent);
		runSwing(() -> tool.addComponentProvider(provider, true));
		waitForSwing();
		Window window = runSwing(() -> tool.getWindowManager().getProviderWindow(provider));
		assertNotNull(window);
		assertNotSame(tool.getToolFrame(), window);
		return window;
	}

	private void setLastActiveWindow(Window window) {
		runSwing(() -> TestUtils.setInstanceField("lastActiveWindow", tool.getWindowManager(),
			window));
	}

	private Window showDialogAndGetOwner() {

		// Replace the focus manager only while the dialog is open, since other tests rely on the
		// state of the real focus manager
		KeyboardFocusManager originalFocusManager =
			KeyboardFocusManager.getCurrentKeyboardFocusManager();
		KeyboardFocusManager.setCurrentKeyboardFocusManager(
			new FakeActiveWindowFocusManager(fakeActiveWindow));
		try {
			TestDialog dialog = new TestDialog();
			executeOnSwingWithoutBlocking(() -> DockingWindowManager.showDialog(dialog));
			waitForDialogComponent(TestDialog.class);
			Window owner =
				runSwing(() -> SwingUtilities.getWindowAncestor(dialog.getComponent()).getOwner());
			runSwing(() -> dialog.close());
			waitForSwing();
			return owner;
		}
		finally {
			KeyboardFocusManager.setCurrentKeyboardFocusManager(originalFocusManager);
			waitForSwing();
		}
	}

	private class DetachedProvider extends ComponentProvider {
		private JPanel panel = new JPanel();
		private boolean canBeParent;

		DetachedProvider(boolean canBeParent) {
			super(tool, "Detached Provider", "Test Owner");
			this.canBeParent = canBeParent;
			panel.setPreferredSize(new Dimension(200, 200));
			setDefaultWindowPosition(WindowPosition.WINDOW);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}

		@Override
		public boolean canBeParent() {
			return canBeParent;
		}
	}

	private static class TestDialog extends DialogComponentProvider {
		TestDialog() {
			super("Test Dialog", true);
			addWorkPanel(new JPanel());
			addCancelButton();
		}
	}

	private static class FakeActiveWindowFocusManager extends DefaultKeyboardFocusManager {
		private Window activeWindow;

		FakeActiveWindowFocusManager(Window activeWindow) {
			this.activeWindow = activeWindow;
		}

		@Override
		public Window getActiveWindow() {
			return activeWindow;
		}
	}
}
