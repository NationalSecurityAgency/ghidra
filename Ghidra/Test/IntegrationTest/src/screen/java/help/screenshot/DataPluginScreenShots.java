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

import javax.swing.JRadioButton;

import org.junit.Test;

import docking.DialogComponentProvider;
import ghidra.util.table.GhidraTable;

public class DataPluginScreenShots extends GhidraScreenShotGenerator {

	public DataPluginScreenShots() {
		super();
	}

	@Test
	public void testCreateStructureDialog() {
		positionListingTop(0x40d3a4);
		makeSelection(0x40d3a4, 0x40d3ab);
		performAction("Create Structure", "DataPlugin", false);
		DialogComponentProvider dialog = getDialog();
		JRadioButton button = (JRadioButton) getInstanceField("exactMatchButton", dialog);
		setSelected(button, true);
		captureDialog(500, 400);
	}

	@Test
	public void testCreateStructureDialogWithTableSelection() {
		positionListingTop(0x40d3a4);
		makeSelection(0x40d3a4, 0x40d3ab);
		performAction("Create Structure", "DataPlugin", false);

		DialogComponentProvider dialog = getDialog();
		JRadioButton button = (JRadioButton) getInstanceField("exactMatchButton", dialog);
		setSelected(button, true);
		GhidraTable table = (GhidraTable) getInstanceField("matchingStructuresTable", dialog);
		selectRow(table, 2);

		captureDialog(500, 400);
	}

	@Test
	public void testDataSelectionSettings() {
		positionListingTop(0x40d3a4);
		makeSelection(0x40d3a4, 0x40d3ab);
		performAction("Data Settings", "DataPlugin", false);
		captureDialog();
	}

	@Test
	public void testDefaultSettings() {
		positionListingTop(0x40d3a4);
		performAction("Default Data Settings", "DataPlugin", false);
		captureDialog();
	}

	@Test
	public void testInstanceSettings() {
		positionListingTop(0x40d3a4);
		performAction("Data Settings", "DataPlugin", false);
		captureDialog();
	}

}
