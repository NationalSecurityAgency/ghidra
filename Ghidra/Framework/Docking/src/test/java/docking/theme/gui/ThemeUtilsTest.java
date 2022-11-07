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
import java.text.ParseException;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.SelectFromListDialog;
import docking.widgets.dialogs.InputDialog;
import generic.theme.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.builtin.MetalTheme;
import generic.theme.builtin.NimbusTheme;

public class ThemeUtilsTest extends AbstractDockingTest {

	private Color testColor = Palette.RED;
	private ThemeManager themeManager;

	@Before
	public void setup() {
		themeManager = ThemeManager.getInstance();
		GTheme nimbusTheme = new NimbusTheme();
		GTheme metalTheme = new MetalTheme();
		themeManager.addTheme(nimbusTheme);
		themeManager.addTheme(metalTheme);
		themeManager.setTheme(nimbusTheme);

		// get rid of any leftover imported themes from previous tests
		Set<GTheme> allThemes = themeManager.getAllThemes();
		for (GTheme theme : allThemes) {
			if (!(theme instanceof DiscoverableGTheme)) {
				themeManager.deleteTheme(theme);
			}
		}
	}

	@Test
	public void testImportThemeNonZip() throws IOException {
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());
		File themeFile = createThemeFile("Bob");
		ThemeUtils.importTheme(themeManager, themeFile);
		assertEquals("Bob", themeManager.getActiveTheme().getName());

	}

	@Test
	public void testImportThemeFromZip() throws IOException {
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());
		File themeFile = createZipThemeFile("zippy");
		ThemeUtils.importTheme(themeManager, themeFile);
		assertEquals("zippy", themeManager.getActiveTheme().getName());
	}

	@Test
	public void testImportThemeWithCurrentChangesCancelled() throws IOException {
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());
		themeManager.setColor("Panel.background", testColor);
		assertTrue(themeManager.hasThemeChanges());

		File themeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(themeManager, themeFile));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "Cancel");
		waitForSwing();
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());
	}

	@Test
	public void testImportThemeWithCurrentChangesSaved() throws IOException {
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());

		// make a change in the current theme, so you get asked to save
		themeManager.setColor("Panel.background", testColor);
		assertTrue(themeManager.hasThemeChanges());

		File themeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(themeManager, themeFile));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "Yes");
		InputDialog inputDialog = waitForDialogComponent(InputDialog.class);
		assertNotNull(inputDialog);
		runSwing(() -> inputDialog.setValue("Joe"));
		pressButtonByText(inputDialog, "OK");
		waitForSwing();
		assertEquals("Bob", themeManager.getActiveTheme().getName());
		assertNotNull(themeManager.getTheme("Joe"));
	}

	@Test
	public void testImportThemeWithCurrentChangesThrownAway() throws IOException {
		assertEquals("Nimbus Theme", themeManager.getActiveTheme().getName());

		// make a change in the current theme, so you get asked to save
		themeManager.setColor("Panel.background", testColor);
		assertTrue(themeManager.hasThemeChanges());

		File bobThemeFile = createThemeFile("Bob");
		runSwingLater(() -> ThemeUtils.importTheme(themeManager, bobThemeFile));

		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull(dialog);
		assertEquals("Save Theme Changes?", dialog.getTitle());
		pressButtonByText(dialog, "No");
		waitForSwing();
		assertEquals("Bob", themeManager.getActiveTheme().getName());
	}

	@Test
	public void testExportThemeAsZip() throws IOException {
		runSwingLater(() -> ThemeUtils.exportTheme(themeManager));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Export Zip");
		ExportThemeDialog exportDialog = waitForDialogComponent(ExportThemeDialog.class);
		File exportFile = createTempFile("whatever", ".theme.zip");
		runSwing(() -> exportDialog.setOutputFile(exportFile));
		pressButtonByText(exportDialog, "OK");
		waitForSwing();
		assertTrue(exportFile.exists());
		GTheme zipTheme = GTheme.loadTheme(exportFile);
		assertEquals("Nimbus Theme", zipTheme.getName());
	}

	@Test
	public void testExportThemeAsFile() throws IOException {
		runSwingLater(() -> ThemeUtils.exportTheme(themeManager));
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Export File");
		ExportThemeDialog exportDialog = waitForDialogComponent(ExportThemeDialog.class);
		File exportFile = createTempFile("whatever", ".theme");
		runSwing(() -> exportDialog.setOutputFile(exportFile));
		pressButtonByText(exportDialog, "OK");
		waitForSwing();
		assertTrue(exportFile.exists());
		GTheme fileTheme = GTheme.loadTheme(exportFile);
		assertEquals("Nimbus Theme", fileTheme.getName());
	}

	@Test
	public void testDeleteTheme() throws IOException {
		File themeFile = createThemeFile("Bob");
		ThemeUtils.importTheme(themeManager, themeFile);
		themeFile = createThemeFile("Joe");
		ThemeUtils.importTheme(themeManager, themeFile);
		themeFile = createThemeFile("Lisa");
		ThemeUtils.importTheme(themeManager, themeFile);

		assertNotNull(themeManager.getTheme("Bob"));
		assertNotNull(themeManager.getTheme("Joe"));
		assertNotNull(themeManager.getTheme("Lisa"));

		runSwingLater(() -> ThemeUtils.deleteTheme(themeManager));
		@SuppressWarnings("unchecked")
		SelectFromListDialog<GTheme> dialog = waitForDialogComponent(SelectFromListDialog.class);
		runSwing(() -> dialog.setSelectedObject(themeManager.getTheme("Bob")));
		pressButtonByText(dialog, "OK");

		OptionDialog optionDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(optionDialog, "Yes");
		waitForSwing();

		assertNotNull(themeManager.getTheme("Bob"));
		assertNull(themeManager.getTheme("Joe"));
		assertNotNull(themeManager.getTheme("Lisa"));

	}

	@Test
	public void testParseGroupings() throws ParseException {
		String source = "(ab (cd))(ef)(( gh))";
		List<String> results = ThemeValueUtils.parseGroupings(source, '(', ')');
		assertEquals(3, results.size());
		assertEquals("ab (cd)", results.get(0));
		assertEquals("ef", results.get(1));
		assertEquals("( gh)", results.get(2));
	}

	@Test
	public void testParseGroupingsWithUnbalancedGroups() {
		String source = "(ab (cd))(ef)( gh))"; // note the groupings are unbalanced
		try {
			ThemeValueUtils.parseGroupings(source, '(', ')');
			fail("Expected parse Exception");
		}
		catch (ParseException e) {
			//expected
		}
	}

	@Test
	public void testParseGroupingsWhenNoGroupingsExist() {
		String source = "xx yy";  // note there are no grouping chars 
		try {
			ThemeValueUtils.parseGroupings(source, '(', ')');
			fail("Expected parse Exception");
		}
		catch (ParseException e) {
			// expected
		}
	}

	private File createZipThemeFile(String themeName) throws IOException {
		File file = createTempFile("Test_Theme", ".theme.zip");
		GTheme outputTheme = new GTheme(file, themeName, LafType.METAL, false);
		outputTheme.addColor(new ColorValue("Panel.Background", testColor));
		new ThemeWriter(outputTheme).writeThemeToZipFile(file);
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
