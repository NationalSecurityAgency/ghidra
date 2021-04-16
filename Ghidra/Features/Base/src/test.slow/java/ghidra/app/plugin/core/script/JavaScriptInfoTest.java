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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.swing.KeyStroke;

import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;

public class JavaScriptInfoTest extends AbstractGhidraScriptMgrPluginTest {

	@Test
	public void testDetailedJavaScript() {
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
			scriptFile = createTempScriptFileWithLines(
				"/*",
				" * This is a test block comment. It will be ignored.",
				" * @category NotTheRealCategory",
				" */",
				"//" + descLine1,
				"//" + descLine2,
				"//" + descLine3,
				"//@author " + author,
				"//@category " + categoryTop + "." + categoryBottom,
				"//@keybinding " + keybinding,
				"//@menupath " + menupath,
				"//@importpackage " + importPackage,
				"class DetailedScript {",
				"  // for a blank class, it sure is well documented!",
				"}");
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
	public void testJavaScriptWithBlockComment() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempScriptFileWithLines(
				"/*",
				" * This is a test block comment. It will be ignored.",
				" * @category NotTheRealCategory",
				" */",
				"//" + description,
				"//@category " + category,
				"class BlockCommentScript {",
				"  // just a blank class, nothing to see here",
				"}");
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
	public void testJavaScriptWithBlockCommentAndCertifyHeader() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempScriptFileWithLines(
				"/* ###" + 
				" * IP: GHIDRA" + 
				" * " +
				" * Some license text..." + 
				" * you may not use this file except in compliance with the License." + 
				" * " +
				" * blah blah blah" +
				" */" +
				" " + 
				"/*",
				" * This is a test block comment. It will be ignored.",
				" * @category NotTheRealCategory",
				" */",
				"//" + description,
				"//@category " + category,
				"class BlockCommentScript {",
				"  // just a blank class, nothing to see here",
				"}");
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
	public void testJavaScriptWithoutBlockComment() {
		String description = "Script without a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempScriptFileWithLines(
				"//" + description,
				"//@category " + category,
				"class NoBlockCommentScript {",
				"  // just a blank class, nothing to see here",
				"}");
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
	public void testJavaScriptWithSingleLineBlockComment() {
		String description = "Script with a block comment at the top.";
		String category = "Test";
		ResourceFile scriptFile = null;

		try {
			//@formatter:off
			scriptFile = createTempScriptFileWithLines(
				"/* This is a test block comment. It will be ignored. */",
				"//" + description,
				"//@category " + category,
				"class SingleLineBlockCommentScript {",
				"  // just a blank class, nothing to see here",
				"}");
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
}
