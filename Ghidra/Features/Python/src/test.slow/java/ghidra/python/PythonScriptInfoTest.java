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
package ghidra.python;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.swing.KeyStroke;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class PythonScriptInfoTest extends AbstractGhidraHeadedIntegrationTest {

	@Before
	public void setUp() throws Exception {
		GhidraScriptUtil.initialize(new BundleHost(), null);
		Path userScriptDir = java.nio.file.Paths.get(GhidraScriptUtil.USER_SCRIPTS_DIR);
		if (Files.notExists(userScriptDir)) {
			Files.createDirectories(userScriptDir);
		}
	}

	@After
	public void tearDown() throws Exception {
		GhidraScriptUtil.dispose();
	}

	@Test
	public void testDetailedPythonScript() {
		String descLine1 = "This script exists to check that the info on";
		String descLine2 = "a script that has extensive documentation is";
		String descLine3 = "properly parsed and represented.";
		String author = "Fake Name";
		String categoryTop = "Test";
		String categoryBottom = "ScriptInfo";
		String keybinding = "ctrl shift COMMA";
		String menupath = "File.Run.Detailed Script";
		String importPackage = "detailStuff";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempPyScriptFileWithLines(
				"'''",
				"This is a test block comment. It will be ignored.",
				"@category NotTheRealCategory",
				"'''",
				"#" + descLine1,
				"#" + descLine2,
				"#" + descLine3,
				"#@author " + author,
				"#@category " + categoryTop + "." + categoryBottom,
				"#@keybinding " + keybinding,
				"#@menupath " + menupath,
				"#@importpackage " + importPackage,
				"print('for a blank class, it sure is well documented!')");
			//@formatter:on
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}

		ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);

		String expectedDescription = descLine1 + " \n" + descLine2 + " \n" + descLine3 + " \n";
		assertEquals(expectedDescription, info.getDescription());

		assertEquals(author, info.getAuthor());
		assertEquals(KeyStroke.getKeyStroke(keybinding), info.getKeyBinding());
		assertEquals(menupath.replace(".", "->"), info.getMenuPathAsString());
		assertEquals(importPackage, info.getImportPackage());

		String[] actualCategory = info.getCategory();
		assertEquals(2, actualCategory.length);
		assertEquals(categoryTop, actualCategory[0]);
		assertEquals(categoryBottom, actualCategory[1]);
	}

	@Test
	public void testPythonScriptWithBlockComment() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempPyScriptFileWithLines(
				"'''",
				"This is a test block comment. It will be ignored.",
				"@category NotTheRealCategory",
				"'''",
				"#" + description,
				"#@category " + category,
				"print 'hello!'");
			//@formatter:on
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}

		ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
		assertEquals(description + " \n", info.getDescription());

		String[] actualCategory = info.getCategory();
		assertEquals(1, actualCategory.length);
		assertEquals(category, actualCategory[0]);
	}

	@Test
	public void testPythonScriptWithBlockCommentAndCertifyHeader() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempPyScriptFileWithLines(
				"## ###",
				"# IP: GHIDRA", 
				"# ",
				"# Some license text...", 
				"# you may not use this file except in compliance with the License.", 
				"# ",
				"# blah blah blah",
				"##",
				"",
				"'''",
				"This is a test block comment. It will be ignored.",
				"@category NotTheRealCategory",
				"'''",
				"#" + description,
				"#@category " + category,
				"print 'hello!'");
			//@formatter:on
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}

		ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
		assertEquals(description + " \n", info.getDescription());

		String[] actualCategory = info.getCategory();
		assertEquals(1, actualCategory.length);
		assertEquals(category, actualCategory[0]);
	}

	@Test
	public void testPythonScriptWithoutBlockComment() {
		String description = "Script without a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempPyScriptFileWithLines(
				"#" + description,
				"#@category " + category,
				"print 'hello!'");
			//@formatter:on
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}

		ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
		assertEquals(description + " \n", info.getDescription());

		String[] actualCategory = info.getCategory();
		assertEquals(1, actualCategory.length);
		assertEquals(category, actualCategory[0]);
	}

	@Test
	public void testPythonScriptWithSingleLineBlockComment() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempPyScriptFileWithLines(
				"'''This is a test block comment. It will be ignored.'''",
				"#" + description,
				"#@category " + category,
				"print 'hello!'");
			//@formatter:on
		}
		catch (IOException e) {
			fail("couldn't create a test script: " + e.getMessage());
		}

		ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
		assertEquals(description + " \n", info.getDescription());

		String[] actualCategory = info.getCategory();
		assertEquals(1, actualCategory.length);
		assertEquals(category, actualCategory[0]);
	}

	private ResourceFile createTempPyScriptFileWithLines(String... lines) throws IOException {
		File scriptDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
		File tempFile = File.createTempFile(testName.getMethodName(), ".py", scriptDir);
		tempFile.deleteOnExit();
		ResourceFile tempResourceFile = new ResourceFile(tempFile);

		PrintWriter writer = new PrintWriter(tempResourceFile.getOutputStream());
		for (String line : lines) {
			writer.println(line);
		}
		writer.close();

		return tempResourceFile;
	}
}
