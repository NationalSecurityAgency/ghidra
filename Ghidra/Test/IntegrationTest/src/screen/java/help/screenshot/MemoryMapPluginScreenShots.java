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

import javax.swing.JComponent;
import javax.swing.table.TableModel;

import org.junit.Test;

import docking.ComponentProvider;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.util.exception.AssertException;
import ghidra.util.table.GhidraTable;

public class MemoryMapPluginScreenShots extends GhidraScreenShotGenerator {

	public MemoryMapPluginScreenShots() {
		super();
	}

@Test
    public void testMemoryMap() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		moveProviderToItsOwnWindow(provider);
		JComponent component = getDockableComponent(provider);

		captureIsolatedComponent(component, 800, 225);
	}

@Test
    public void testAddMemoryBlock() {

		performAction("Add Block", "MemoryMapPlugin", false);

		captureDialog();
	}

@Test
    public void testBitOverlayAddresses() {

		//Draw empty white rectangle		
		image = new BufferedImage(450, 175, BufferedImage.TYPE_INT_ARGB);
		Graphics g = image.getGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, 450, 175);

		//Draw Title and subtitle
		drawText("Bit Overlay Addresses", Color.BLACK, new Point(160, 30), 18);
		drawText("Byte Memory", Color.BLACK, new Point(15, 30), 10);
		drawText("Addresses", Color.BLACK, new Point(20, 40), 10);

		//Draw text inside and next to boxes
		drawText("00008100", Color.BLACK, new Point(15, 80), 12);
		drawText("00008100", Color.BLACK, new Point(15, 130), 12);

		drawText("MSB", Color.BLACK, new Point(90, 60), 10);
		drawText("LSB", Color.BLACK, new Point(370, 60), 10);

		drawText("0007", Color.BLACK, new Point(90, 80), 10);
		drawText("0006", Color.BLACK, new Point(130, 80), 10);
		drawText("0005", Color.BLACK, new Point(170, 80), 10);
		drawText("0004", Color.BLACK, new Point(210, 80), 10);
		drawText("0003", Color.BLACK, new Point(250, 80), 10);
		drawText("0002", Color.BLACK, new Point(290, 80), 10);
		drawText("0001", Color.BLACK, new Point(330, 80), 10);
		drawText("0000", Color.BLACK, new Point(370, 80), 10);

		drawText("000f", Color.BLACK, new Point(90, 130), 10);
		drawText("000e", Color.BLACK, new Point(130, 130), 10);
		drawText("000d", Color.BLACK, new Point(170, 130), 10);
		drawText("000c", Color.BLACK, new Point(210, 130), 10);
		drawText("000b", Color.BLACK, new Point(250, 130), 10);
		drawText("000a", Color.BLACK, new Point(290, 130), 10);
		drawText("0009", Color.BLACK, new Point(330, 130), 10);
		drawText("0008", Color.BLACK, new Point(370, 130), 10);

		//Draw boxes		
		Point p1 = new Point(80, 65);
		Point p2 = new Point(400, 65);
		Point p3 = new Point(400, 90);
		Point p4 = new Point(80, 90);

		Point p5 = new Point(80, 115);
		Point p6 = new Point(400, 115);
		Point p7 = new Point(400, 140);
		Point p8 = new Point(80, 140);

		drawLine(Color.BLACK, 1, p1, p2);
		drawLine(Color.BLACK, 1, p2, p3);
		drawLine(Color.BLACK, 1, p3, p4);
		drawLine(Color.BLACK, 1, p4, p1);

		drawLine(Color.BLACK, 1, p5, p6);
		drawLine(Color.BLACK, 1, p6, p7);
		drawLine(Color.BLACK, 1, p7, p8);
		drawLine(Color.BLACK, 1, p8, p5);

		for (int i = 1; i < 8; i++) {
			drawLine(Color.BLACK, 1, new Point(80 + i * 40, 65), new Point(80 + i * 40, 90));
			drawLine(Color.BLACK, 1, new Point(80 + i * 40, 115), new Point(80 + i * 40, 140));
		}
	}

@Test
    public void testAddMappedBlock() {

		performAction("Add Block", "MemoryMapPlugin", false);

		DialogComponentProvider dialog = getDialog();
		GhidraComboBox<?> comboBox = (GhidraComboBox<?>) getInstanceField("comboBox", dialog);
		selectItem(comboBox, "Byte Mapped");

		captureDialog();

		drawRectangleAround(comboBox, Color.GREEN, 10);
	}

@Test
    public void testMoveMemory() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		JComponent component = provider.getComponent();
		GhidraTable table = findComponent(component, GhidraTable.class);
		waitForSwing();

		selectRow(table, ".text");
		waitForSwing();

		DockingAction action = (DockingAction) getInstanceField("moveAction", provider);
		performAction(action, false);

		captureDialog();
	}

@Test
    public void testSplitMemoryBlock() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		JComponent component = provider.getComponent();
		GhidraTable table = findComponent(component, GhidraTable.class);
		waitForSwing();

		selectRow(table, ".text");
		waitForSwing();

		DockingAction action = (DockingAction) getInstanceField("splitAction", provider);
		performAction(action, false);

		captureDialog();
	}

@Test
    public void testMemoryExpandUp() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		JComponent component = provider.getComponent();
		GhidraTable table = findComponent(component, GhidraTable.class);
		waitForSwing();

		selectRow(table, ".text");
		waitForSwing();

		DockingAction action = (DockingAction) getInstanceField("expandUpAction", provider);
		performAction(action, false);

		captureDialog();
	}

@Test
    public void testMemoryExpandDown() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		JComponent component = provider.getComponent();
		GhidraTable table = findComponent(component, GhidraTable.class);
		waitForSwing();

		selectRow(table, ".text");
		waitForSwing();

		DockingAction action = (DockingAction) getInstanceField("expandDownAction", provider);
		performAction(action, false);

		captureDialog();
	}

@Test
    public void testSetImageBaseDialog() {

		performAction("Memory Map", "DockingWindows", true);

		ComponentProvider provider = getProvider("Memory Map");
		JComponent component = provider.getComponent();
		GhidraTable table = findComponent(component, GhidraTable.class);
		waitForSwing();

		selectRow(table, ".text");
		waitForSwing();

		DockingAction action = (DockingAction) getInstanceField("setBaseAction", provider);
		performAction(action, false);

		captureDialog();
	}

	private void selectRow(final GhidraTable table, final String text) {

		final TableModel model = table.getModel();
		runSwing(new Runnable() {

			@Override
			public void run() {
				int columnCount = model.getColumnCount();
				int columnIndex = -1;
				int rowIndex = -1;
				for (int i = 0; i < columnCount; i++) {
					if (model.getColumnName(i).equals("Name")) {
						columnIndex = i;
						break;
					}
				}
				if (columnIndex != -1) {
					int rowCount = model.getRowCount();
					for (int i = 0; i < rowCount; i++) {
						if (model.getValueAt(i, columnIndex).equals(text)) {
							rowIndex = i;
							break;
						}
					}
				}
				if (rowIndex == -1) {
					throw new AssertException();
				}
				table.selectRow(rowIndex);

			}
		});
	}

	private void selectItem(final GhidraComboBox<?> comboBox, final String text) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				int itemCount = comboBox.getItemCount();
				Object item = null;
				for (int i = 0; i < itemCount; i++) {
					Object itemAt = comboBox.getItemAt(i);
					if (itemAt.toString().equals(text)) {
						item = itemAt;
						break;
					}
				}
				if (item == null) {
					throw new AssertException();
				}
				comboBox.setSelectedItem(item);
			}
		});
	}
}
