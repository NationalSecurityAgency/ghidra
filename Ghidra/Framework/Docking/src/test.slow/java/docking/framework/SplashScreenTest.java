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
package docking.framework;

import static org.junit.Assert.*;

import java.awt.Frame;
import java.awt.Window;

import javax.swing.*;

import org.junit.After;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import docking.*;
import docking.test.AbstractDockingTest;
import docking.widgets.PasswordDialog;
import generic.test.category.NightlyCategory;
import ghidra.util.Msg;

// The splash screen is sensitive to windows being activated/deactivated, so don't run
// when other test windows may be open
@Category(NightlyCategory.class)
public class SplashScreenTest extends AbstractDockingTest {

	private AboutDialog aboutDialog;

	@After
	public void tearDown() {
		Msg.debug(this, "tearDown() - open windows before closing");
		printOpenWindows();

		runSwing(() -> SplashScreen.disposeSplashScreen());

		closeAllWindows();
		printOpenWindows();

		Msg.debug(this, "tearDown() - open windows after closing");
	}

	@Test
	public void testShowInfoWindow() throws Exception {
		// no parent
		showModalInfoWindow(null);

		ensureInfoWindowVisible();
		hideInfoWindow();

		// not visible parent
		JFrame parentFrame = new JFrame("InfoWindowTest.testShowInfoWindow Frame");
		parentFrame.setBounds(-100, -100, 0, 0);
		showModalInfoWindow(parentFrame);

		ensureInfoWindowVisible();
		hideInfoWindow();

		// visible parent
		parentFrame.setVisible(true);
		showModalInfoWindow(parentFrame);

		ensureInfoWindowVisible();
		hideInfoWindow();
	}

	@Test
	public void testShowAndHideSplashScreen() {
		showSplashScreen(true);
		ensureSpashScreenVisible(true);

		showSplashScreen(false);
		ensureSpashScreenVisible(false);

		showSplashScreen(true);
		ensureSpashScreenVisible(true);

		showSplashScreen(false);
		ensureSpashScreenVisible(false);
	}

	@Test
	public void testUpdateSplashScreenStatus() {
		showSplashScreen(true);
		ensureSpashScreenVisible(true);

		JLabel statusLabel = (JLabel) getInstanceField("statusLabel", SplashScreen.class);

		// now change the text and make sure that it took effect
		String newStatusText = "New Status Text";
		SplashScreen.updateSplashScreenStatus(newStatusText);

		String updatedText = statusLabel.getText().trim();

		assertEquals("The text of the label does not match the updated " + "text that was passed.",
			newStatusText, updatedText);

		showSplashScreen(false);
	}

	/*
	 * Test that the modal password dialog does not get hidden behind the
	 * splash screen.
	 *
	 * @since Tracker Id 275
	 */
	@Test
	public void testSplashScreenPasswordModality_SharedParent() throws Exception {

		showSplashScreen(true);
		ensureSpashScreenVisible(true);

		// show a modal dialog with no parent (this will use the Splash Screen's parent)
		showModalPasswordDialog(null);

		// When the splash screen and the dialog share a parent, then the dialog should NOT
		// cause the splash screen to go away
		ensureSpashScreenVisible(true);
	}

	@Test
	public void testSplashScreenPasswordModality_UnsharedParent() throws Exception {
		// show the splash screen
		showSplashScreen(true);
		ensureSpashScreenVisible(true);

		DockingFrame frame = new DockingFrame("Modal Parent Frame");
		frame.setVisible(true);
		showModalPasswordDialog(frame);

		ensureSplashScreenWillClose();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void ensureSplashScreenWillClose() {
		waitForCondition(() -> {
			SplashScreen splash = getSplash();
			return splash == null;
		}, "The splash screen did not close.\nOpen Windows:\n" + getOpenWindowsAsString());
	}

	private DockingDialog showModalPasswordDialog(Frame parentFrame) throws Exception {
		String dialogTitle = "InfoWindowTest.testSplashScreenPasswordModality() Dialog";
		DialogComponentProvider passwordDialog = runSwing(() -> new PasswordDialog(dialogTitle,
			"Server Type", "Server Name", "Prompt", null, null));

		executeOnSwingWithoutBlocking(
			() -> DockingWindowManager.showDialog(parentFrame, passwordDialog));

		JDialog dialog = waitForJDialog(dialogTitle);
		assertNotNull(dialog);

		Window dialogWindow = SwingUtilities.windowForComponent(dialog);
		Msg.debug(this, "Created modal dialog with parent: " + getTitleForWindow(dialogWindow) +
			" - id: " + System.identityHashCode(dialogWindow));

		return (DockingDialog) dialog;
	}

	// handles showing the modal info window, which must be done from a  thread outside of the
	// test thread
	private void showModalInfoWindow(final JFrame parentFrame) {
		// create a thread to show the modal dialog so that the current thread doesn't block
		aboutDialog = runSwing(() -> new AboutDialog());
		executeOnSwingWithoutBlocking(() -> DockingWindowManager.showDialog(null, aboutDialog));
	}

	private void showSplashScreen(final boolean makeVisible) {

		if (makeVisible) {
			SplashScreen splash = runSwing(() -> SplashScreen.showSplashScreen());
			assertNotNull("Failed showing splash screen", splash);
			return;
		}
		SplashScreen.disposeSplashScreen();
	}

	private void ensureSpashScreenVisible(boolean visible) {
		// get the 'splashWindow' and make sure that it is not null and that it is visible
		SplashScreen splashScreen = getSplash();

		if (!visible) {
			assertNull("The splash screen is visible; it should have been hidden.", splashScreen);
			return;
		}

		if (splashScreen == null) {
			printOpenWindows();
			fail("The splash screen has not been shown or has been hidden--it is null");
		}

		// timing issue debug
		waitForCondition(() -> splashScreen.isVisible());

		if (!splashScreen.isVisible()) {

			// this can happen if other OS windows trigger the splash window to be hidden
			printOpenWindows();
			fail("The splash screen is not visible when expected to be so - " + splashScreen);
		}
	}

	private void ensureInfoWindowVisible() {
		// get the 'infoDialog' and make sure that it is not null and that it is visible
		assertTrue("The info dialog is not visible after it was supposed to " + "have been shown.",
			aboutDialog.isVisible());
	}

	private void hideInfoWindow() throws Exception {
		runSwing(() -> aboutDialog.close());
	}

	private SplashScreen getSplash() {
		SplashScreen splash = runSwing(() -> {
			return (SplashScreen) getInstanceField("splashWindow", SplashScreen.class);
		});
		return splash;
	}
}
