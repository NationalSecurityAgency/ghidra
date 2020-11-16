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

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.*;

import org.junit.Test;

import docking.DockableComponent;
import docking.widgets.fieldpanel.FieldPanel;
import ghidra.GhidraOptions;
import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;

public class CodeBrowserPluginScreenShots extends GhidraScreenShotGenerator {

	private FieldPanel fieldPanel;
	private CodeBrowserPlugin plugin;

	public CodeBrowserPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {

		super.setUp();
		plugin = getPlugin(tool, CodeBrowserPlugin.class);
		fieldPanel = plugin.getFieldPanel();

	}

	@Test
	public void testCaptureClosedStructure() {
		removeFlowArrows();

		long structAddr = 0x0040be45;
		createDetailedStructure(structAddr);

		positionListingTop(0x0040be40);
		goToListing(structAddr, AddressFieldFactory.FIELD_NAME, false);

		Rectangle cursor = getCursorBounds();
		captureListingRange(0x0040be40, 0x0040be56, 600);
		drawBorder(Color.BLACK);

		drawTextWithArrowNearOpenStructureIcon("Closed", cursor);

	}

	@Test
	public void testCaptureOpenStructure() {
		removeFlowArrows();

		long structAddr = 0x0040be45;
		createDetailedStructure(structAddr);

		positionListingTop(0x0040be40);
		positionCursor(structAddr, OpenCloseFieldFactory.FIELD_NAME);
		leftClickCursor();
		positionCursor(structAddr, AddressFieldFactory.FIELD_NAME);

		Rectangle cursor = getCursorBounds();
		captureListingRange(0x0040be40, 0x0040be56, 600);

		drawBorder(Color.BLACK);

		drawTextWithArrowNearOpenStructureIcon("Open", cursor);
	}

	private void drawTextWithArrowNearOpenStructureIcon(String text, Rectangle cursorBounds) {
		//
		// Make some room to draw our annotations (text and an arrow)
		//
		Dimension whitespace = new Dimension(150, 10);
		padImage(Color.WHITE, whitespace.height, whitespace.width, 10, 10);

		//
		// Draw text inside of the newly padded space
		//
		int arrowStartY = 40;
		int textStartX = 20;
		int textStartY = arrowStartY - 4;// up just a bit
		Point textPoint = new Point(textStartX, textStartY);
		int size = 24;
		Color textColor = Color.MAGENTA.darker();
		drawText(text, textColor, textPoint, size);

		//
		// Draw an arrow from the text above to the 'open structure' icon
		//
		int arrowStartX = 60;
		Color arrowColor = Color.GREEN.darker();
		Point arrowStart = new Point(arrowStartX, arrowStartY);
		int addressFieldStartX = 40;
		int listingOffsetX = whitespace.width;
		int listingOffsetY = whitespace.height;
		int arrowEndX = listingOffsetX + (cursorBounds.x - addressFieldStartX);// a bit of fudge
		int arrowEndY = listingOffsetY + (cursorBounds.y + (cursorBounds.height / 2));
		Point arrowEnd = new Point(arrowEndX, arrowEndY);
		drawArrow(arrowColor, arrowStart, arrowEnd);
	}

	@Test
	public void testCaptureCodeBrowser_OperandHighlight() {
		setToolSize(1000, 800);

		positionListingTop(0x0405352);
		positionCursor(0x0405354, OperandFieldFactory.FIELD_NAME);
		middleClickCursor();

		captureListingRange(0x0405352, 0x0405398, 700);
	}

	@Test
	public void testCaptureSelectionTable() {
		setToolSize(1100, 700);
		positionListingTop(0x0406bd7);
		makeSelection(0x0406be1, 0x0406bf1);

		performAction("Create Table From Selection", "CodeBrowserPlugin", true);
		Window window = waitForWindowByTitleContaining("Selection Table");
		Point loc = plugin.getListingPanel().getLocationOnScreen();
		Dimension size = window.getSize();
		window.setBounds(loc.x + 300, loc.y + 150, size.width, 300);
		captureProvider(CodeViewerProvider.class);
	}

	@Test
	public void testCaptureCodeBrowser() {
		closeProvider(DataTypesProvider.class);
		goToListing(0x0408363);
		captureToolWindow(1000, 500);
	}

	@Test
	public void testCaptureCodeBrowserColors() {
		showOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		captureDialog(1020, 630);
	}

	@Test
	public void testCaptureCodeBrowserReferencePopup() {
		closeProvider(DataTypesProvider.class);
		closeProvider(ViewManagerComponentProvider.class);
		removeFlowArrows();
		removeField("Bytes");
		setToolSize(1000, 600);

		positionListingTop(0x00404936);
		positionCursor(0x00404946, OperandFieldFactory.FIELD_NAME);
		Rectangle cursor = getCursorBounds();
		initiateHover(cursor);
		resizeHoverWindow();

		paintFix(null);// This doesn't use its parameter right now
		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		captureProviderWithScreenShot(provider);
	}

	@Test
	public void testCaptureCodeBrowserWithFlowArrows() {
		long topAddr = 0x00040a435L;
		long bottomAddr = 0x00040a454L;
		long conditionalJumpAddr = 0x040a442;
		long unconditionalJumpAddr = 0x040a44e;

		positionListingTop(topAddr);
		positionCursor(conditionalJumpAddr);
		Rectangle conditional = getCursorBounds();

		positionCursor(unconditionalJumpAddr);
		Rectangle unconditional = getCursorBounds();

		captureListingRange(topAddr, bottomAddr, 600);

		int padX = 100;
		padImage(Color.LIGHT_GRAY, 0, padX, 0, 0);
		int y = conditional.y + 10;
		drawText("Conditional", Color.BLACK, new Point(10, y), 12);
		drawText("    Jump", Color.BLACK, new Point(10, y + 15), 12);

		y = unconditional.y + 10;
		drawText("Unconditional", Color.BLACK, new Point(10, y), 12);
		drawText("    Jump", Color.BLACK, new Point(10, y + 15), 12);

	}

	@Test
	public void testCaptureCodeBrowserWithMarkers() throws Exception {
		createBookmark(0x41cea0);
		createBookmark(0x41ceaa);
		performMemorySearch("61 73");
		waitForTasks();

		positionListingTop(0x41ce9f);
		captureIsolatedProvider(CodeViewerProvider.class, 700, 550);
	}

	@Test
	public void testCaptureDataTypeHover() {
		removeFlowArrows();
		setToolSize(875, 500);
		long structAddr = 0x0040be45;
		createDetailedStructure(structAddr);

		positionListingTop(0x0040be43);
		positionCursor(structAddr, MnemonicFieldFactory.FIELD_NAME);
		Rectangle cursor = getCursorBounds();
		initiateHover(cursor);
		JWindow popup = (JWindow) waitForWindowByName("ListingHoverProvider");
		paintFix(popup);
		captureProvider(CodeViewerProvider.class);

		CodeViewerProvider provider = getProvider(CodeViewerProvider.class);
		captureProviderWithScreenShot(provider);
	}

	@Test
	public void testCaptureHighlight_Example() {
		setToolSize(1000, 800);

		positionListingTop(0x040364c);
		createComment(0x403653, CodeUnit.PRE_COMMENT, "PUSH some stuff");

		positionCursor(0x0403653, MnemonicFieldFactory.FIELD_NAME);
		middleClickCursor();

		captureListingRange(0x040364c, 0x040366f, 700);
	}

	@Test
	public void testCaptureMarkerPopup() {
		setToolSize(1400, 1200);
		ListingPanel listingPanel = plugin.getListingPanel();
		List<OverviewProvider> overviewProviders = listingPanel.getOverviewProviders();
		assertEquals(1, overviewProviders.size());

		OverviewProvider provider = overviewProviders.get(0);
		rightClick(provider.getComponent(), 1, 1);

		captureMenu();
	}

	@Test
	public void testCaptureMouseHoverButton() {
		setToolSize(500, 400);
		CodeViewerProvider provider = plugin.getProvider();
		JButton button = findProviderToolBarButton(provider, "Toggle Mouse Hover Popups");
		Rectangle bounds = button.getBounds();
		Point p = bounds.getLocation();
		DockableComponent dockableComponent = getDockableComponent(provider);
		dockableComponent.getHeader().setSelected(true);

		p = SwingUtilities.convertPoint(button.getParent(), p, dockableComponent);

		captureProvider(CodeViewerProvider.class);

		int width = image.getWidth(null);
		crop(new Rectangle(0, 0, width, 30));
		drawOval(new Color(107, 47, 109),
			new Rectangle(p.x - 13, p.y - 1, bounds.width + 26, bounds.height + 2), 4);

	}

	@Test
	public void testCaptureNavigationMarkerOptions() {
		showOptions("Navigation Markers");
		captureDialog(600, 500);
	}

	@Test
	public void testCaptureOpenHeader() {
		performAction("Toggle Header", "CodeBrowserPlugin", true);
		goToListing(0x00400280);
		CodeViewerProvider provider = plugin.getProvider();
		JButton button = findProviderToolBarButton(provider, "Toggle Header");
		Rectangle bounds = button.getBounds();
		Point p = bounds.getLocation();
		DockableComponent dockableComponent = getDockableComponent(provider);
		dockableComponent.getHeader().setSelected(true);

		p = SwingUtilities.convertPoint(button.getParent(), p, dockableComponent);

		captureProvider(CodeViewerProvider.class);

		int x = p.x - 18;
		int y = p.y - 2;
		int height = bounds.height + 12;
		int width = bounds.width + 34;
		Color color = new Color(120, 0, 64);
		drawOval(color, new Rectangle(x, y, width, height), 5);

		int arrowHeadX = x + (width / 4);
		int spacer = 4;
		int ovalBottom = y + height + spacer;
		int length = 75;
		int offset = 30;// tilt the arrow a bit
		Point arrorTop = new Point(arrowHeadX - offset, ovalBottom + length);
		Point arrowBottom = new Point(arrowHeadX, ovalBottom);
		drawArrow(color, arrorTop, arrowBottom);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void resizeHoverWindow() {
		final Window window = waitForWindowByName("ListingHoverProvider");
		runSwing(() -> window.setSize(650, 350));
		waitForSwing();

	}

	private void initiateHover(final Rectangle cursor) {
		runSwing(() -> {
			ActionListener al = (ActionListener) getInstanceField("hoverHandler", fieldPanel);
			setInstanceField("lastMouseMovedEvent", al,
				new MouseEvent(fieldPanel, 0, 0L, 0, cursor.x + 1, cursor.y + 1, 0, false));
			al.actionPerformed(null);
		});
	}

	private void createDetailedStructure(long address) {
		goToListing(address);
		StructureDataType struct = new StructureDataType("MyStruct", 0);
		struct.add(new ByteDataType(), "byte1", "This is a comment for the byte datatype");
		struct.add(new DoubleDataType(), "????", "Not sure what this double is for");
		struct.add(new WordDataType(), "User ID", null);
		struct.setDescription(
			"This comment describes my struct and spans multiple lines. This structure\nis for demonstration purposes only.");
		CreateDataCmd createDataCmd = new CreateDataCmd(addr(address), struct);
		tool.execute(createDataCmd, program);
		waitForBusyTool(tool);
	}

	private void createComment(long address, int commentType, String comment) {
		goToListing(address);
		SetCommentCmd cmd = new SetCommentCmd(addr(address), commentType, comment);
		tool.execute(cmd, program);
		waitForBusyTool(tool);
	}
}
