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

import javax.swing.JFrame;
import javax.swing.JLabel;

import org.junit.*;

import docking.test.AbstractDockingTest;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.util.bean.GGlassPane;

/**
 * Tests the {@link StatusBar} class.
 * 
 * 
 * @since  Tracker Id 323
 */
public class StatusBarTest extends AbstractDockingTest {

	private StatusBar statusBar;
	private JFrame testFrame;

	@Before
	public void setUp() throws Exception {

		testFrame = new JFrame("StatusBar Test");
		testFrame.setGlassPane(new GGlassPane());
		testFrame.setSize(400, 100);
		statusBar = new StatusBar();
		testFrame.getContentPane().add(statusBar);
		testFrame.setVisible(true);
	}

	@After
	public void tearDown() throws Exception {

		testFrame.dispose();
	}

	/*
	 * Test method for 'addStatusItem(JComponent, boolean, boolean)' and 
	 * 'removeStatusItem(JComponent)'.
	 */
	@Test
	public void testAddAndRemoveStatusItem() {

		// test while not visible
		addAndRemoveStatusItems();

		// re-run the tests while visible
		testFrame.setVisible(true);

		addAndRemoveStatusItems();
	}

	/*
	 * Test method for 'setStatusText(String)' and 'getToolTipText()' methods.
	 */
	@Test
	public void testSetStatusText() {

		String testText1 = "Some test status text...";
		setStatusText(testText1);

		// make sure the tooltip text is updated
		String tooltipText = statusBar.getToolTipText();

		assertTrue("The tooltip text was not updated with the current " + "status message.",
			(tooltipText.indexOf(testText1) > -1));

		testFrame.setVisible(true);

		String testText2 = "More test status text...";
		setStatusText(testText2);
		tooltipText = statusBar.getToolTipText();

		// get the tooltip text and make sure that both messages are presented
		assertTrue("The tooltip text was not updated with the current " + "status message.",
			(tooltipText.indexOf(testText1) > -1));
		assertTrue("The tooltip text was not updated with the current " + "status message.",
			(tooltipText.indexOf(testText2) > -1));
	}

	private void addAndRemoveStatusItems() {
		final JLabel label1 = new GDLabel("Test Label 1");
		final JLabel label2 = new GDLabel("Test Label 2");

		// normal add/remove operations
		runSwing(() -> {
			statusBar.addStatusItem(label1, true, true);
			statusBar.addStatusItem(label2, true, true);
		});

		runSwing(() -> {
			statusBar.removeStatusItem(label1);
			statusBar.removeStatusItem(label2);
		});

		// method call variations
		runSwing(() -> {
			statusBar.addStatusItem(label1, false, true);
			statusBar.addStatusItem(label2, true, false);
		});

		runSwing(() -> {
			statusBar.removeStatusItem(label1);
			statusBar.removeStatusItem(label2);
		});

		// repeat adding
		runSwing(() -> {
			statusBar.addStatusItem(label1, true, true);
			statusBar.addStatusItem(label1, true, true);
		});

		// removing non-existent elements        
		runSwing(() -> statusBar.removeStatusItem(label2));

		runSwing(() -> {
			try {
				statusBar.removeStatusItem(new GLabel("Test Label 3"));

				Assert.fail("Did not receive an expected NullPointerException.");
			}
			catch (NullPointerException npe) {
				// expected, caused by a null parent
			}
		});
	}

	private void setStatusText(final String text) {
		runSwing(() -> statusBar.setStatusText(text));
		waitForSwing();
	}
}
