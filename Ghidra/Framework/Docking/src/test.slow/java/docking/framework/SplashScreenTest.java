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

// The splash screen is sensitive to windows being activated/deactivated, so don't run
// when other test windows may be open
@Category(NightlyCategory.class)
public class SplashScreenTest extends AbstractDockingTest {

	@After
	public void tearDown() {
		runSwing(() -> SplashScreen.disposeSplashScreen());
		disposeAllWindows();
	}

	private void disposeAllWindows() {
		for (Window window : getAllWindows()) {
			runSwing(window::dispose);
		}
	}

	@Test
	public void testShowAndHideSplashScreen() {
		showSplashScreen(true);
		assertSpashScreenVisible(true);

		showSplashScreen(false);
		assertSpashScreenVisible(false);

		showSplashScreen(true);
		assertSpashScreenVisible(true);

		showSplashScreen(false);
		assertSpashScreenVisible(false);
	}

	@Test
	public void testUpdateSplashScreenStatus() {
		showSplashScreen(true);
		assertSpashScreenVisible(true);

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
		assertSpashScreenVisible(true);

		// show a modal dialog with no parent (this will use the Splash Screen's parent)
		showModalPasswordDialog(null);

		// When the splash screen and the dialog share a parent, then the dialog should NOT
		// cause the splash screen to go away
		assertSpashScreenVisible(true);
	}

	@Test
	public void testSplashScreenPasswordModality_UnsharedParent() throws Exception {
		// show the splash screen
		showSplashScreen(true);
		assertSpashScreenVisible(true);

		DockingFrame frame = new DockingFrame("Modal Parent Frame");
		show(frame);
		showModalPasswordDialog(frame);

		ensureSplashScreenWillClose();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void show(JFrame frame) {
		runSwing(() -> frame.setVisible(true));
	}

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

		if (parentFrame == null) {
			// null means to share the parent
			Object splashParent = getInstanceField("hiddenFrame", SplashScreen.class);
			parentFrame = (Frame) splashParent;
		}

		Frame finalParent = parentFrame;
		executeOnSwingWithoutBlocking(
			() -> {
				DockingDialog dialog =
					DockingDialog.createDialog(finalParent, passwordDialog, finalParent);
				dialog.setVisible(true);
			});

		JDialog dialog = waitForJDialog(dialogTitle);
		assertNotNull(dialog);

		return (DockingDialog) dialog;
	}

	private void showSplashScreen(final boolean makeVisible) {

		if (makeVisible) {
			SplashScreen splash = runSwing(() -> SplashScreen.showSplashScreen());
			assertNotNull("Failed showing splash screen", splash);
			waitForSwing();
			return;
		}
		SplashScreen.disposeSplashScreen();
		waitForSwing();
	}

	private void assertSpashScreenVisible(boolean visible) {
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
	}

	private SplashScreen getSplash() {
		SplashScreen splash = runSwing(() -> {
			return (SplashScreen) getInstanceField("splashWindow", SplashScreen.class);
		});
		return splash;
	}
}
