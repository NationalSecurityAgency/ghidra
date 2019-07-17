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

import java.awt.Component;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.Test;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.util.importer.LibrarySearchPathManager;
import ghidra.app.util.opinion.*;
import ghidra.plugin.importer.ImporterDialog;
import ghidra.plugin.importer.ImporterLanguageDialog;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.lang.LanguageCompilerSpecPair;

public class ImporterPluginScreenShots extends GhidraScreenShotGenerator {

	public ImporterPluginScreenShots() {
		super();
	}

	@Test
	public void testImporterDialog() throws Exception {
		performAction("Import File", "ImporterPlugin", false);
		selectFileForImport("WinHelloCPP.exe");

		redactImportDialog();

		captureDialog();
	}

	@Test
	public void testBatchImportDialog() throws Exception {
		performAction("Batch Import", "ImporterPlugin", false);
		selectDirForBatchImport("WinHelloCPP.exe");

		redactImportSource();

		captureDialog(850, 500);
	}

	@Test
	public void testSearchPathsDialog() throws Exception {
		LibrarySearchPathManager.setLibraryPaths(new String[] { ".", "/Users/Joe" });
		runSwing(() -> {
			LibraryPathsDialog dialog = new LibraryPathsDialog();
			tool.showDialog(dialog);
		}, false);
		waitForDialogComponent(LibraryPathsDialog.class);
		captureDialog();
	}

	@Test
	public void testLanguagePickerDialog() throws Exception {
		PeLoader peLoader = new PeLoader();
		List<LoadSpec> loadSpecs = new ArrayList<>();
		loadSpecs.add(new LoadSpec(peLoader, 0,
			new LanguageCompilerSpecPair("x86:LE:32:default", "windows"), true));
		loadSpecs.add(new LoadSpec(peLoader, 0,
			new LanguageCompilerSpecPair("x86:LE:32:default", "gcc"), false));
		loadSpecs.add(new LoadSpec(peLoader, 0,
			new LanguageCompilerSpecPair("x86:LE:32:default", "borland"), false));
		loadSpecs.add(new LoadSpec(peLoader, 0,
			new LanguageCompilerSpecPair("x86:LE:32:System Management Mode", "default"), false));
		runSwing(() -> {
			ImporterLanguageDialog dialog = new ImporterLanguageDialog(loadSpecs, tool, null);
			dialog.show(null);
		}, false);
		waitForDialogComponent(ImporterLanguageDialog.class);
		captureDialog();
	}

	private ImporterDialog selectFileForImport(String fileToImport) throws Exception {
		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		File testDataFile = getTestDataFile(fileToImport);
		fileChooser.setSelectedFile(testDataFile);
		waitForUpdateOnChooser(fileChooser);

		pressButtonByName(fileChooser.getComponent(), "OK");

		ImporterDialog importerDialog = waitForDialogComponent(ImporterDialog.class);
		assertNotNull(importerDialog);
		return importerDialog;
	}

	private BatchImportDialog selectDirForBatchImport(String rootDir) throws Exception {
		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		File testDataFile = getTestDataDir("pe");
		fileChooser.setSelectedFile(testDataFile);
		waitForUpdateOnChooser(fileChooser);

		pressButtonByName(fileChooser.getComponent(), "OK");

		BatchImportDialog dialog = waitForDialogComponent(BatchImportDialog.class);
		assertNotNull(dialog);
		return dialog;
	}

	private void redactImportSource() {

		BatchImportDialog dialog = waitForDialogComponent(BatchImportDialog.class);

		JList<?> list = (JList<?>) findComponentByName(dialog, "batch.import.source.list");

		runSwing(() -> {
			list.setCellRenderer(new DefaultListCellRenderer() {
				@Override
				public Component getListCellRendererComponent(JList<? extends Object> theList,
						Object value, int index, boolean isSelected, boolean cellHasFocus) {

					JLabel renderer = (JLabel) super.getListCellRendererComponent(theList, value,
						index, isSelected, cellHasFocus);
					renderer.setText("/Users/Joe/dir/with/binaries");
					return renderer;
				}
			});
		});
		list.repaint();
	}

	private void redactImportDialog() {

		ImporterDialog dialog = waitForDialogComponent(ImporterDialog.class);

		runSwing(() -> {
			String title = dialog.getTitle();
			int indexOf = title.indexOf("/Ghidra/Test");
			title = title.substring(indexOf);
			dialog.setTitle(title);
		});
	}

}
