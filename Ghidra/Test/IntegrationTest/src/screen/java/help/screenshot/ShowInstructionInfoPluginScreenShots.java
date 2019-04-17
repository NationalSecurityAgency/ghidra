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

import java.awt.*;
import java.net.URL;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import org.junit.Test;

import docking.*;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.field.Field;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.processors.ShowInstructionInfoPlugin;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;
import ghidra.app.util.viewer.field.MnemonicFieldFactory;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.util.LaunchErrorDialog;

public class ShowInstructionInfoPluginScreenShots extends GhidraScreenShotGenerator {

	private ShowInstructionInfoPlugin plugin;

	public ShowInstructionInfoPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		plugin = getPlugin(tool, ShowInstructionInfoPlugin.class);
	}

	@Test
	public void testProcessorManualOptions() {

		showOptions("Processor Manuals");

		captureDialog(800, 354);

//		finished("ShowInstructionInfoPlugin", "ProcessorManualOptions.png");
	}

	@Test
	public void testRawInstructionDisplay() {

		closeProvider(ViewManagerComponentProvider.class);
		closeProvider(DataTypesProvider.class);

		setToolSize(975, 325);

		CodeViewerProvider listing = getProvider(CodeViewerProvider.class);

		goToListing(0x40100d, MnemonicFieldFactory.FIELD_NAME, true);

		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		ListingPanel listingPanel = cb.getListingPanel();
		Window window = windowForComponent(listing.getComponent());
		captureWindow(window);

		Graphics2D g = (Graphics2D) image.getGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		Rectangle labelBounds = getInstructionLabelBounds(); // the label in the status bar
		Point location = labelBounds.getLocation();

		// move over a bit so the oval doesn't overwrite the text
		int labelPadding = 10;
		location.x -= labelPadding * 2;
		location.y -= labelPadding * 1.5; // a bit of fudge here; trial and error
		Dimension labelSize = labelBounds.getSize();
		labelSize.width += labelPadding;
		labelSize.height += (1.85 * labelPadding); // a bit of fudge here; trial and error
		Rectangle shapeBounds = new Rectangle(location, labelSize);

		int thickness = 5;
		drawRectangle(Color.RED, shapeBounds, thickness);

		Point start = getEndOfRow(cb, listingPanel, window);
		Point end = new Point(location.x, location.y);
		drawLine(Color.RED, thickness, start, end);

		cropListingWithStatusArea();

//		finished("ShowInstructionInfoPlugin", "RawInstructionDisplay.png");
	}

	@Test
	public void testShowInstructionInfo() {

		goToListing(0x40100d, MnemonicFieldFactory.FIELD_NAME, true);

		performAction("Show Instruction Info", plugin.getName(), true);

		captureProviderWindow("Instruction Info", 1200, 500);

//		finished("ShowInstructionInfoPlugin", "ShowInstructionInfo.png");
	}

	@Test
	public void testUnableToLaunch() throws Exception {

		URL url1 = new URL("http://localhost:11046/1234567//pentium.pdf#page=701");
		URL url2 = new URL("file:/Ghidra/docs/manuals/pentium.pdf#page=701");
		final LaunchErrorDialog dialog = new LaunchErrorDialog(url1, url2);

		runSwing(() -> dialog.setVisible(true), false);

		captureDialog(dialog);

//		finished("ShowInstructionInfoPlugin", "ShowInstructionInfo.png");
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Rectangle getInstructionLabelBounds() {
		JLabel label = (JLabel) getInstanceField("instructionLabel", plugin);
		Window window = windowForComponent(label);
		Rectangle bounds = label.getBounds();
		return SwingUtilities.convertRectangle(label.getParent(), bounds, window);
	}

	private void cropListingWithStatusArea() {
		CodeBrowserPlugin cb = getPlugin(tool, CodeBrowserPlugin.class);
		ListingPanel listingPanel = cb.getListingPanel();
		Window window = windowForComponent(listingPanel);

		StatusBar statusBar = getStatusBar();
		int statusHeight = statusBar.getHeight();
		DockableComponent dc = getDockableComponent(listingPanel);
		Rectangle cropBounds = dc.getBounds();
		cropBounds = SwingUtilities.convertRectangle(dc.getParent(), cropBounds, window);
		cropBounds.height += statusHeight;
		crop(cropBounds);
	}

	private StatusBar getStatusBar() {
		DockingWindowManager windowManager = tool.getWindowManager();
		Object root = getInstanceField("root", windowManager);
		StatusBar statusBar = (StatusBar) getInstanceField("statusBar", root);
		return statusBar;
	}

	private Point getEndOfRow(CodeBrowserPlugin cb, ListingPanel listingPanel, Window window) {
		Layout layout = listingPanel.getLayout(cb.getCurrentAddress());
		int numFields = layout.getNumFields();

		// note: The y of the field bounds always starts at 0.  So, we have to use the cursor
		//       bounds, whose y is correct, which we can do, since we put the cursor on the
		//       line in which we are interested.
		Point cursorPoint = listingPanel.getCursorPoint();
		Rectangle fieldBounds = layout.getFieldBounds(numFields - 1);
		fieldBounds.y = cursorPoint.y;

		// find the *visible* width of the field (it is longer than the text)
		Field field = layout.getField(numFields - 1);
		int charCount = field.getNumCols(numFields - 1);
		int x = field.getX(0, charCount);
		fieldBounds.width = x - fieldBounds.x;

		// offset a bit from the end, so the line doesn't touch the text
		int padding = 10;
		Point start = new Point(fieldBounds.x + fieldBounds.width + padding,
			fieldBounds.y + (fieldBounds.height / 2));

		FieldPanel fieldPanel = listingPanel.getFieldPanel();
		start = SwingUtilities.convertPoint(fieldPanel, start, window);
		return start;
	}

//	private void bob() {
//
//		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
//		Window window = SwingUtilities.windowForComponent(provider.getComponent());
//		final JDialog dialog = new JDialog(window);
//		dialog.setModal(true);
//
//		JPanel panel = new JPanel(new BorderLayout());
//		JButton button = new JButton("Repaint");
//		button.addActionListener(new ActionListener() {
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				new Thread() {
//					@Override
//					public void run() {
//						Thread.currentThread().setName(
//							"Show Image[" + System.identityHashCode(this) + "]");
//
//						doIt();
//						showImage("ShowInstructionInfoPlugin", "RawInstructionDisplay.png");
//					}
//				}.start();
//			}
//		});
//
//		JButton closeButton = new JButton("Close");
//		closeButton.addActionListener(new ActionListener() {
//			@Override
//			public void actionPerformed(ActionEvent e) {
//				dialog.setVisible(false);
//			}
//		});
//
//		panel.add(button);
//		panel.add(closeButton, BorderLayout.SOUTH);
//		dialog.getContentPane().add(panel);
//
//		dialog.setSize(300, 200);
//		dialog.setLocation(1300, 100);
//		dialog.setVisible(true);
//	}
}
