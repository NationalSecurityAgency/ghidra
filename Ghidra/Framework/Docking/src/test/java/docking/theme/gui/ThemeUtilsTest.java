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
package docking.theme.gui;

import static org.junit.Assert.*;

import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.SelectFromListDialog;
import docking.widgets.dialogs.InputDialog;
import generic.theme.*;
import generic.theme.builtin.MetalTheme;
import generic.theme.builtin.NimbusTheme;

public class ThemeUtilsTest extends AbstractDockingTest {

	@Before
	public void setup() {
		GTheme nimbusTheme = new NimbusTheme();
		GTheme metalTheme = new MetalTheme();
		Gui.addTheme(nimbusTheme);
		Gui.addTheme(metalTheme);
		Gui.setTheme(nimbusTheme);

		// get rid of any leftover imported themes from previous tests
		Set<GTheme> allThemes = Gui.getAllThemes();
		for (GTheme gTheme : allThemes) {
			if (gTheme instanceof FileGTheme fileTheme) {
				Gui.deleteTheme(fileTheme);
			}
		}
	}

	@Test
	public void testImportThemeNonZip() throws IOException {
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());
		File themeFile = createThemeFile("Bob");
		ThemeUtils.importTheme(themeFile);
		assertEquals("Bob", Gui.getActiveTheme().getName());

	}

	@Test
	public void testImportThemeFromZip() throws IOException {
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());
		File themeFile = createZipThemeFile("zippy");
		ThemeUtils.importTheme(themeFile);
		assertEquals("zippy", Gui.getActiveTheme().getName());
	}

	@Test
	public void testImportThemeWithCurrentChangesCancelled() throws IOException {
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());
		Gui.setColor("Panel.background", Color.RED);
		assertTrue(Gui.hasThemeChanges());

		File themeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(themeFile));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "Cancel");
		waitForSwing();
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());
	}

	@Test
	public void testImportThemeWithCurrentChangesSaved() throws IOException {
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());

		// make a change in the current theme, so you get asked to save
		Gui.setColor("Panel.background", Color.RED);
		assertTrue(Gui.hasThemeChanges());

		File themeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(themeFile));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "Yes");
		InputDialog inputDialog = waitForDialogComponent(InputDialog.class);
		assertNotNull(inputDialog);
		runSwing(() -> inputDialog.setValue("Joe"));
		pressButtonByText(inputDialog, "OK");
		waitForSwing();
		assertEquals("Bob", Gui.getActiveTheme().getName());
		assertNotNull(Gui.getTheme("Joe"));
	}

	@Test
	public void testImportThemeWithCurrentChangesThrownAway() throws IOException {
		assertEquals("Nimbus Theme", Gui.getActiveTheme().getName());

		// make a change in the current theme, so you get asked to save
		Gui.setColor("Panel.background", Color.RED);
		assertTrue(Gui.hasThemeChanges());

		File bobThemeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(bobThemeFile));

		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "No");
		waitForSwing();
		assertEquals("Bob", Gui.getActiveTheme().getName());
	}

	@Test
	public void testExportThemeAsZip() throws IOException {
		runSwingLater(() -> ThemeUtils.exportTheme());
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Export Zip");
		ExportThemeDialog exportDialog = waitForDialogComponent(ExportThemeDialog.class);
		File exportFile = createTempFile("whatever", ".theme.zip");
		runSwing(() -> exportDialog.setOutputFile(exportFile));
		pressButtonByText(exportDialog, "OK");
		waitForSwing();
		assertTrue(exportFile.exists());
		ZipGTheme zipTheme = new ZipGTheme(exportFile);
		assertEquals("Nimbus Theme", zipTheme.getName());
	}

	@Test
	public void testExportThemeAsFile() throws IOException {
		runSwingLater(() -> ThemeUtils.exportTheme());
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Export File");
		ExportThemeDialog exportDialog = waitForDialogComponent(ExportThemeDialog.class);
		File exportFile = createTempFile("whatever", ".theme");
		runSwing(() -> exportDialog.setOutputFile(exportFile));
		pressButtonByText(exportDialog, "OK");
		waitForSwing();
		assertTrue(exportFile.exists());
		FileGTheme fileTheme = new FileGTheme(exportFile);
		assertEquals("Nimbus Theme", fileTheme.getName());
	}

	@Test
	public void testDeleteTheme() throws IOException {
		File themeFile = createThemeFile("Bob");
		ThemeUtils.importTheme(themeFile);
		themeFile = createThemeFile("Joe");
		ThemeUtils.importTheme(themeFile);
		themeFile = createThemeFile("Lisa");
		ThemeUtils.importTheme(themeFile);

		assertNotNull(Gui.getTheme("Bob"));
		assertNotNull(Gui.getTheme("Joe"));
		assertNotNull(Gui.getTheme("Lisa"));

		runSwingLater(() -> ThemeUtils.deleteTheme());
		@SuppressWarnings("unchecked")
		SelectFromListDialog<GTheme> dialog = waitForDialogComponent(SelectFromListDialog.class);
		runSwing(() -> dialog.setSelectedObject(Gui.getTheme("Bob")));
		pressButtonByText(dialog, "OK");

		OptionDialog optionDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(optionDialog, "Yes");
		waitForSwing();

		assertNotNull(Gui.getTheme("Bob"));
		assertNull(Gui.getTheme("Joe"));
		assertNotNull(Gui.getTheme("Lisa"));

	}

	private File createZipThemeFile(String themeName) throws IOException {
		File file = createTempFile("Test_Theme", ".theme.zip");
		ZipGTheme zipGTheme = new ZipGTheme(file, themeName, LafType.METAL, false);
		zipGTheme.addColor(new ColorValue("Panel.Background", Color.RED));
		zipGTheme.save();
		return file;
	}

	private File createThemeFile(String themeName) throws IOException {
		String themeData = createThemeDataString(themeName);
		File file = createTempFile("Test_Theme", ".theme");
		FileUtils.writeStringToFile(file, themeData, Charset.defaultCharset());
		return file;
	}

	private String createThemeDataString(String themeName) {
		String themeData = """
				name = THEMENAME
				lookAndFeel = Metal
				useDarkDefaults = false
				[color]Panel.background = #ffcccc
				""";

		return themeData.replace("THEMENAME", themeName);
	}

}
