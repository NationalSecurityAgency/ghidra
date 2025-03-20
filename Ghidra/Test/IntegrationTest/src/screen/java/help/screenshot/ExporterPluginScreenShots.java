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

import java.io.IOException;

import javax.swing.JComboBox;

import org.junit.Test;

import ghidra.app.plugin.core.exporter.ExporterDialog;
import ghidra.app.util.OptionsDialog;
import ghidra.app.util.exporter.Exporter;
import ghidra.framework.model.*;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class ExporterPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testExport_Dialog() {

		// override the user of 'user.home' in the dialog
		Preferences.setProperty(Preferences.LAST_EXPORT_DIRECTORY, "/path");

		DomainFile df = createDomainFile();
		ExporterDialog dialog = new ExporterDialog(tool, df);
		runSwing(() -> tool.showDialog(dialog), false);
		waitForSwing();
		captureDialog(dialog);
	}

	@Test
	public void testAscii_Options() throws Exception {
		performAction("Export Program", "ExporterPlugin", false);
		ExporterDialog d = waitForDialogComponent(ExporterDialog.class);

		chooseExporter(d, "Ascii");
		OptionsDialog optionDialog = waitForDialogComponent(OptionsDialog.class);

		captureDialog(optionDialog);
	}

	@Test
	public void testC_Options() throws Exception {
		performAction("Export Program", "ExporterPlugin", false);
		ExporterDialog d = waitForDialogComponent(ExporterDialog.class);

		chooseExporter(d, "C/C++");
		OptionsDialog optionDialog = waitForDialogComponent(OptionsDialog.class);

		captureDialog(optionDialog);
	}

	@Test
	public void testIntel_Hex_Options() throws Exception {
		performAction("Export Program", "ExporterPlugin", false);
		ExporterDialog d = waitForDialogComponent(ExporterDialog.class);

		chooseExporter(d, "Intel Hex");
		OptionsDialog optionDialog = waitForDialogComponent(OptionsDialog.class);

		captureDialog(optionDialog);
	}

	private void chooseExporter(ExporterDialog d, String formatName) {
		JComboBox<?> exportersCombo = findComponent(d, JComboBox.class);
		setSelectedExporter(exportersCombo, formatName);
		pressButtonByText(d.getComponent(), "Options...", false);
	}

	private void setSelectedExporter(final JComboBox<?> exportersCombo, final String exporterName) {
		runSwing(() -> {
			for (int i = 0; i < exportersCombo.getItemCount(); ++i) {
				Object obj = exportersCombo.getItemAt(i);
				if (obj instanceof Exporter) {
					Exporter exp = (Exporter) obj;
					if (exp.getName().equals(exporterName)) {
						exportersCombo.setSelectedItem(exp);
						return;
					}
				}
			}
		});
	}

	private DomainFile createDomainFile() {
		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "Project");
		DomainFile df = new TestDummyDomainFile(root, "Program_A") {
			@Override
			public Class<? extends DomainObject> getDomainObjectClass() {
				return Program.class;
			}

			@Override
			public DomainObject getImmutableDomainObject(Object consumer, int version,
					TaskMonitor monitor) throws VersionException, IOException, CancelledException {
				try {
					return createDefaultProgram(getName(),
						getSLEIGH_8051_LANGUAGE().getLanguageID().toString(), consumer);
				}
				catch (Exception e) {
					failWithException("Unexpected exception", e);
					return null;
				}
			}

		};
		return df;
	}

}
