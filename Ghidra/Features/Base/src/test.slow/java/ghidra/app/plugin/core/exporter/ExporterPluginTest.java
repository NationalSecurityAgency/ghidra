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
package ghidra.app.plugin.core.exporter;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.swing.JButton;
import javax.swing.JComboBox;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.util.PluginConstants;
import ghidra.app.util.exporter.Exporter;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;

public class ExporterPluginTest extends AbstractProgramBasedTest {

	protected ExporterPlugin exporterPlugin;

	/**
	 * Sets up the plugin for the tests.
	 *
	 * @throws Exception
	 */
	@Before
	public void setUp() throws Exception {
		initialize();
		exporterPlugin = getPlugin(tool, ExporterPlugin.class);
	}

	@Override
	protected String getProgramName() {
		return "notepad";
	}

	@Override
	protected Program getProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._X86);
		builder.createMemory("test", "0x01001000", 0x100);

		return builder.getProgram();
	}

	protected ExporterDialog performExport() {
		ComponentProvider provider = tool.getComponentProvider(PluginConstants.CODE_BROWSER);
		DockingActionIf action = getAction(exporterPlugin, "Export Program");
		performAction(action, provider, false);
		return waitForDialogComponent(ExporterDialog.class);
	}

	@Override
	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testExportEnabled() throws Exception {
		ExporterDialog d = performExport();
		JButton okButton = findButtonByText(d, "OK");
		assertEnabled(okButton, true);
	}

	@Test
	public void testExportEnabledWhenDirectoryNameMatchesText() throws Exception {
		ExporterDialog d = performExport();

		// create a directory for testing
		Path tmpdir = Paths.get(System.getProperty("java.io.tmpdir"));
		File newDirectory = tmpdir.resolve("TextDirMatchTest" + getProgramName()).toFile();
		newDirectory.mkdir();
		newDirectory.deleteOnExit();

		// set the export to the new directory
		d.getOutputFileTextField().setText(newDirectory.getAbsolutePath());

		JButton okButton = findButtonByText(d, "OK");
		assertEnabled(okButton, true);
	}

	@Test
	public void testExportDisabledWhenDirectoryNameMatchesExport() throws Exception {
		ExporterDialog d = performExport();

		// get the appropriate extension
		JComboBox<Exporter> exporterBox = d.getExporterComboBox();
		String extension = "." + ((Exporter)exporterBox.getSelectedItem()).getDefaultFileExtension();

		// create a directory for testing
		Path tmpdir = Paths.get(System.getProperty("java.io.tmpdir"));
		String dirNameWithoutExtension = "ExportDirMatchTest" + getProgramName();
		File newDirectory = tmpdir.resolve(dirNameWithoutExtension + extension).toFile();
		newDirectory.mkdir();
		newDirectory.deleteOnExit();

		// set the export to the new directory (without the extension)
		String newDirectoryPath = tmpdir.resolve(dirNameWithoutExtension).toFile().getAbsolutePath();
		d.getOutputFileTextField().setText(newDirectoryPath);

		JButton okButton = findButtonByText(d, "OK");
		assertEnabled(okButton, false);
	}

	@Test
	public void testExportEnabledWhenReadOnlyFileMatchesText() throws Exception {
		ExporterDialog d = performExport();

		// create a read-only file for testing
		File roFile = File.createTempFile("TextFileMatchTest" + getProgramName(), "");
		roFile.setWritable(false);
		roFile.deleteOnExit();

		// set the export to the new read-only file
		d.getOutputFileTextField().setText(roFile.getAbsolutePath());

		JButton okButton = findButtonByText(d, "OK");
		assertEnabled(okButton, true);
	}

	@Test
	public void testExportDisabledWhenReadOnlyFileNameMatchesExport() throws Exception {
		ExporterDialog d = performExport();

		// get the appropriate extension
		JComboBox<Exporter> exporterBox = d.getExporterComboBox();
		String extension = "." + ((Exporter)exporterBox.getSelectedItem()).getDefaultFileExtension();

		// create a read-only file for testing
		File roFile = File.createTempFile("ExportFileMatchTest" + getProgramName(), extension);
		roFile.setWritable(false);
		roFile.deleteOnExit();

		// set the export to the new file (without the extension)
		String newFilePath = roFile.getAbsolutePath();
		d.getOutputFileTextField().setText(newFilePath.substring(0, newFilePath.lastIndexOf(extension)));

		JButton okButton = findButtonByText(d, "OK");
		assertEnabled(okButton, false);
	}
}
