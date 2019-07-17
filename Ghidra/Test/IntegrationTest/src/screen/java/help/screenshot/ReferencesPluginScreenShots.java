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
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.swing.*;

import org.junit.Test;

import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.references.*;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.LoaderService;
import ghidra.framework.main.DataTreeDialog;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class ReferencesPluginScreenShots extends GhidraScreenShotGenerator {

	public ReferencesPluginScreenShots() {
		super();
	}

	@Test
	public void testAddReferenceDialog() {
		goToListing(0x401008);
		performAction("Add Reference From", "ReferencesPlugin", false);
		captureDialog();
	}

	@Test
	public void testChoose_external_prog() throws Exception {
		importFile(getTestDataFile("pe/w7sp1/user32.dll"));
		importFile(getTestDataFile("pe/w7sp1/shlwapi.dll"));

		runSwing(() -> {
			DataTreeDialog dialog = new DataTreeDialog(tool.getToolFrame(),
				"Choose External Program (" + "Kernel32.dll" + ")", DataTreeDialog.OPEN);
			tool.showDialog(dialog);
		}, false);
		captureDialog();
	}

	@Test
	public void testCreateOffsetTable() {
		goToListing(0x400fd0);
		makeSelection(0x400fd0, 0x400fd8);
		performAction("Create Offset References", "OffsetTablePlugin", false);
		JDialog d = waitForJDialog("Create Offset References");
		captureDialog();
		pressButtonByText(d, "Cancel");
	}

	@Test
	public void testDropZones() {
		goToListing(0x4010ae);

		performAction("View/Edit References From", "ReferencesPlugin", false);
		EditReferencesProvider provider = getProvider(EditReferencesProvider.class);
		captureIsolatedProvider(provider, 700, 300);
		captureProvider(provider);
		int topMargin = 60;
		int leftMargin = 10;
		padImage(Color.WHITE, topMargin, leftMargin, 10, 10);
		JComponent rootComp = getDockableComponent(EditReferencesProvider.class);
		JComponent comp =
			(JComponent) findComponentByName(provider.getComponent(), "operandLabels[0]");
		Point origin = new Point(leftMargin, topMargin);
		explainComponent(rootComp, comp, Color.GREEN, origin, new Point(250, 20),
			"Operand-specific Drop Zones");
		comp = (JComponent) findComponentByName(provider.getComponent(), "mnemonicLabel");
		explainComponent(rootComp, comp, Color.GREEN, origin, new Point(250, 20),
			"Operand-specific Drop Zones");

		comp = (JComponent) findComponentByName(provider.getComponent(), "RefsTable");
		explainComponent(rootComp, comp, Color.GREEN, origin, new Point(450, 40),
			"Active-operand Drop Zones");

	}

	private void explainComponent(JComponent rootComp, JComponent comp, Color color, Point origin,
			Point point, String text) {
		Rectangle bounds = getBounds(comp);
		Rectangle converted = SwingUtilities.convertRectangle(comp.getParent(), bounds, rootComp);
		converted.x += origin.x;
		converted.y += origin.y;
		drawRectangle(color, converted, 2);
		Point startLine = new Point(converted.x + converted.width / 2, converted.y);
		drawLine(color, 2, startLine, point);
		Point p2 = new Point(point.x + 20, point.y);
		drawLine(color, 2, point, p2);
		Point p3 = new Point(p2.x + 4, p2.y + 5);
		drawText(text, Color.BLACK, p3, 12f);
	}

	@Test
	public void testExternal_names_dialog() {
		showProvider(ExternalReferencesProvider.class);
		captureProvider(ExternalReferencesProvider.class);
	}

	@Test
	public void testExtRefPanel() {
		goToListing(0x0401008);

		CodeUnit cu = program.getListing().getCodeUnitAt(addr(0x401008));
		ReferencesPlugin plugin = getPlugin(tool, ReferencesPlugin.class);
		final EditReferenceDialog dialog = new EditReferenceDialog(plugin);
		dialog.initDialog(cu, 0, 0, null);
		runSwing(() -> {
			JRadioButton choiceButton = (JRadioButton) getInstanceField("extRefChoice", dialog);
			invokeInstanceMethod("refChoiceActivated", dialog,
				new Class<?>[] { JRadioButton.class }, new Object[] { choiceButton });
		}, true);
		showDialogWithoutBlocking(tool, dialog);

		JPanel panel = (JPanel) getInstanceField("extRefPanel", dialog);
		Rectangle bounds = panel.getBounds();
		bounds = SwingUtilities.convertRectangle(panel.getParent(), bounds, null);
		captureDialog();
		takeSnippet(bounds);
	}

	@Test
	public void testOffsetRefsExample() throws MemoryAccessException { // gif
		removeFlowArrows();
		goToListing(0x0400280);
		int id = program.startTransaction("Test");
		Memory memory = program.getMemory();
		memory.setByte(addr(0x400284), (byte) 0x14);
		memory.setByte(addr(0x400288), (byte) 0x18);
		memory.setByte(addr(0x40028c), (byte) 0x1c);
		memory.setByte(addr(0x400290), (byte) 0x20);
		program.endTransaction(id, true);
		makeSelection(0x400284, 0x400293);

		performAction("Create Offset References", "OffsetTablePlugin", false);
		runSwing(() -> {
			OffsetTableDialog dialog = (OffsetTableDialog) getDialog();
			dialog.setBaseAddress(addr(0x4f5000));
		});
		pressOkOnDialog();
		captureIsolatedProvider(CodeViewerProvider.class, 800, 600);
	}

	@Test
	public void testRefProvider() {
		goToListing(0x402355);
		performAction("View/Edit References From", "ReferencesPlugin", false);
		EditReferencesProvider provider = getProvider(EditReferencesProvider.class);
		captureIsolatedProvider(provider, 700, 400);
	}

	@Test
	public void testRegRefPanel() {
		goToListing(0x0401008);

		CodeUnit cu = program.getListing().getCodeUnitAt(addr(0x401008));
		ReferencesPlugin plugin = getPlugin(tool, ReferencesPlugin.class);
		final EditReferenceDialog dialog = new EditReferenceDialog(plugin);
		dialog.initDialog(cu, 0, 0, null);
		runSwing(() -> {
			JRadioButton choiceButton = (JRadioButton) getInstanceField("regRefChoice", dialog);
			invokeInstanceMethod("refChoiceActivated", dialog,
				new Class<?>[] { JRadioButton.class }, new Object[] { choiceButton });
		}, true);
		showDialogWithoutBlocking(tool, dialog);

		JPanel panel = (JPanel) getInstanceField("regRefPanel", dialog);
		Rectangle bounds = panel.getBounds();
		bounds.height = bounds.height / 2;
		bounds = SwingUtilities.convertRectangle(panel.getParent(), bounds, null);
		captureDialog();
		takeSnippet(bounds);
	}

	@Test
	public void testStackRefPanel() {
		goToListing(0x0401008);

		CodeUnit cu = program.getListing().getCodeUnitAt(addr(0x401008));
		ReferencesPlugin plugin = getPlugin(tool, ReferencesPlugin.class);
		final EditReferenceDialog dialog = new EditReferenceDialog(plugin);
		dialog.initDialog(cu, 0, 0, null);
		runSwing(() -> {
			JRadioButton choiceButton = (JRadioButton) getInstanceField("stackRefChoice", dialog);
			invokeInstanceMethod("refChoiceActivated", dialog,
				new Class<?>[] { JRadioButton.class }, new Object[] { choiceButton });
		}, true);
		showDialogWithoutBlocking(tool, dialog);

		JPanel panel = (JPanel) getInstanceField("stackRefPanel", dialog);
		Rectangle bounds = panel.getBounds();
		bounds.height = bounds.height / 2;
		bounds = SwingUtilities.convertRectangle(panel.getParent(), bounds, null);
		captureDialog();
		takeSnippet(bounds);
	}

	@Test
	public void testMemRefPanel() {
		goToListing(0x0401008);

		CodeUnit cu = program.getListing().getCodeUnitAt(addr(0x401008));
		ReferencesPlugin plugin = getPlugin(tool, ReferencesPlugin.class);
		final EditReferenceDialog dialog = new EditReferenceDialog(plugin);
		dialog.initDialog(cu, 0, 0, null);
		runSwing(() -> {
			JRadioButton choiceButton = (JRadioButton) getInstanceField("memRefChoice", dialog);
			invokeInstanceMethod("refChoiceActivated", dialog,
				new Class<?>[] { JRadioButton.class }, new Object[] { choiceButton });
		}, true);
		showDialogWithoutBlocking(tool, dialog);

		final JPanel panel = (JPanel) getInstanceField("memRefPanel", dialog);
		JButton button = (JButton) getInstanceField("addrHistoryButton", panel);
		Rectangle buttonBounds = button.getBounds();
		buttonBounds = SwingUtilities.convertRectangle(button.getParent(), buttonBounds, panel);
		buttonBounds.x += 20;  // padding added by takeSnippet
		buttonBounds.y += buttonBounds.height / 2 + 20;  // half button height + padding added by takeSnippet()
		System.out.println("Button bounds = " + buttonBounds);
		Rectangle bounds = panel.getBounds();
		bounds.height = 3 * bounds.height / 5;  // get rid of empty space
		bounds = SwingUtilities.convertRectangle(panel.getParent(), bounds, null);
		captureDialog();
		takeSnippet(bounds);
		Image image1 = image;

		runSwing(() -> {
			JCheckBox checkbox = (JCheckBox) getInstanceField("offsetCheckbox", panel);
			checkbox.setSelected(true);
		});
		bounds = panel.getBounds();
		bounds.height = 3 * bounds.height / 5;
		bounds = SwingUtilities.convertRectangle(panel.getParent(), bounds, null);
		captureDialog();
		takeSnippet(bounds);

		Image image2 = image;
		int gap = 40;
		int width = image1.getWidth(null);
		int height = image1.getHeight(null);
		BufferedImage newImage = createEmptyImage(width, 2 * height + gap);

		Graphics2D g2 = (Graphics2D) newImage.getGraphics();
		g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
			RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
		g2.drawImage(image1, 0, 0, null);
		g2.drawImage(image2, 0, height + gap, null);
		g2.setColor(Color.BLACK);
		String label = "Address History";
		int x = 150;
		int y = height + gap / 2;
		g2.drawString(label, x, y);
		x += g2.getFontMetrics().stringWidth(label) + 5;
		y -= g2.getFontMetrics().getAscent() / 3;
		g2.drawLine(x, y, x + 10, y);
		x += 10;
		g2.drawLine(buttonBounds.x, buttonBounds.y, x, y);
		g2.drawLine(buttonBounds.x, buttonBounds.y + height + gap, x, y);
		image = newImage;

	}

	private void importFile(File file) throws CancelledException, DuplicateNameException,
			InvalidNameException, VersionException, IOException {
		String programNameOverride = null;
		List<Program> programs = AutoImporter.importFresh(file, null, this, new MessageLog(),
			TaskMonitor.DUMMY, LoaderService.ACCEPT_ALL, LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED,
			programNameOverride, OptionChooser.DEFAULT_OPTIONS,
			MultipleProgramsStrategy.ALL_PROGRAMS);
		Program p = programs.get(0);
		env.getProject().getProjectData().getRootFolder().createFile(p.getName(), p,
			TaskMonitor.DUMMY);
	}

}
