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

import java.io.File;
import java.util.Iterator;

import javax.swing.JDialog;
import javax.swing.JTextField;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.*;

public class FindAndReplaceCommentScriptTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String FIND_DIALOG_TITLE = "Enter Search String";
	private static final String REPLACE_DIALOG_TITLE = "Enter Replace String";
	private static final int[] COMMENT_TYPES = { CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT,
		CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT };
	private static final int SCRIPT_TIMEOUT = 100000;

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private File script;
	private ToyProgramBuilder builder;
	private Listing listing;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
		listing = program.getListing();

		tool = env.launchDefaultTool(program);

		String scriptPath = "ghidra_scripts/FindAndReplaceCommentScript.java";
		ResourceFile scriptResource = Application.getModuleFile("Base", scriptPath);
		script = scriptResource.getFile(true);
	}

	private Program buildProgram() throws Exception {
		builder = new ToyProgramBuilder("ReplaceCommentTest", true, this);
		builder.createMemory(".text", "0x1001000", 0x4000);

		builder.createComment("0x01001000", "EOL Comment", CodeUnit.EOL_COMMENT);
		builder.createComment("0x01001100", "Pre Comment", CodeUnit.PRE_COMMENT);
		builder.createComment("0x01001200", "Post Comment", CodeUnit.POST_COMMENT);
		builder.createComment("0x01001300", "Plate Comment", CodeUnit.PLATE_COMMENT);
		builder.createComment("0x01001400", "Repeatable Comment", CodeUnit.REPEATABLE_COMMENT);
		builder.createComment("0x01001500", "EOL Comment Repeated", CodeUnit.EOL_COMMENT);
		builder.createComment("0x01001600", "EOL Comment Repeated", CodeUnit.EOL_COMMENT);
		builder.createComment("0x01001700", "Generic Comment Repeated", CodeUnit.EOL_COMMENT);
		builder.createComment("0x01001800", "Generic Comment Repeated", CodeUnit.PRE_COMMENT);
		builder.createComment("0x01001900", "Generic Comment Repeated", CodeUnit.POST_COMMENT);
		builder.createComment("0x01002000", "Generic Comment Repeated", CodeUnit.PLATE_COMMENT);
		builder.createComment("0x01002100", "Generic Comment Repeated",
			CodeUnit.REPEATABLE_COMMENT);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testReplaceEOLComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001000, "EOL Comment", CodeUnit.EOL_COMMENT);

		respondToDialog("EOL Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001000, "New Value", CodeUnit.EOL_COMMENT);
	}

	@Test
	public void testReplacePreComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001100, "Pre Comment", CodeUnit.PRE_COMMENT);

		respondToDialog("Pre Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001100, "New Value", CodeUnit.PRE_COMMENT);
	}

	@Test
	public void testReplacePostComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001200, "Post Comment", CodeUnit.POST_COMMENT);

		respondToDialog("Post Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001200, "New Value", CodeUnit.POST_COMMENT);
	}

	@Test
	public void testReplacePlateComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001300, "Plate Comment", CodeUnit.PLATE_COMMENT);

		respondToDialog("Plate Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001300, "New Value", CodeUnit.PLATE_COMMENT);
	}

	@Test
	public void testReplaceRepeatableComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001400, "Repeatable Comment", CodeUnit.REPEATABLE_COMMENT);

		respondToDialog("Repeatable Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001400, "New Value", CodeUnit.REPEATABLE_COMMENT);
	}

	@Test
	public void testReplaceMultipleCommentsSameType() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001500, "EOL Comment Repeated", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001600, "EOL Comment Repeated", CodeUnit.EOL_COMMENT);

		respondToDialog("EOL Comment Repeated", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001500, "New Value", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001600, "New Value", CodeUnit.EOL_COMMENT);
	}

	@Test
	public void testReplaceMultipleCommentsDifferentTypes() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001700, "Generic Comment Repeated", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001800, "Generic Comment Repeated", CodeUnit.PRE_COMMENT);
		assertCommentEquals(0x01001900, "Generic Comment Repeated", CodeUnit.POST_COMMENT);
		assertCommentEquals(0x01002000, "Generic Comment Repeated", CodeUnit.PLATE_COMMENT);
		assertCommentEquals(0x01002100, "Generic Comment Repeated", CodeUnit.REPEATABLE_COMMENT);

		respondToDialog("Generic Comment Repeated", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001700, "New Value", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001800, "New Value", CodeUnit.PRE_COMMENT);
		assertCommentEquals(0x01001900, "New Value", CodeUnit.POST_COMMENT);
		assertCommentEquals(0x01002000, "New Value", CodeUnit.PLATE_COMMENT);
		assertCommentEquals(0x01002100, "New Value", CodeUnit.REPEATABLE_COMMENT);
	}

	@Test
	public void testReplaceNonexistantComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		respondToDialog("This Value Does Not Exist", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		assertCommentDoesNotExists("New Value");
	}

	@Test
	public void testReplacePartialComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001000, "EOL Comment", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001100, "Pre Comment", CodeUnit.PRE_COMMENT);
		assertCommentEquals(0x01001200, "Post Comment", CodeUnit.POST_COMMENT);
		assertCommentEquals(0x01001300, "Plate Comment", CodeUnit.PLATE_COMMENT);
		assertCommentEquals(0x01001400, "Repeatable Comment", CodeUnit.REPEATABLE_COMMENT);

		respondToDialog("Comment", FIND_DIALOG_TITLE);
		respondToDialog("Test", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001000, "EOL Test", CodeUnit.EOL_COMMENT);
		assertCommentEquals(0x01001100, "Pre Test", CodeUnit.PRE_COMMENT);
		assertCommentEquals(0x01001200, "Post Test", CodeUnit.POST_COMMENT);
		assertCommentEquals(0x01001300, "Plate Test", CodeUnit.PLATE_COMMENT);
		assertCommentEquals(0x01001400, "Repeatable Test", CodeUnit.REPEATABLE_COMMENT);
	}

	private void respondToDialog(String response, String titleValue) {
		JDialog askStringDialog = waitForJDialog(null, titleValue, 3000);
		JTextField textField = findComponent(askStringDialog, JTextField.class);
		setText(textField, response);
		pressButtonByText(askStringDialog, "OK");
	}

	private void assertCommentEquals(int commentAddress, String commentValue, int commentType) {
		Address address = program.getMinAddress().getNewAddress(commentAddress);
		String existingComment = listing.getComment(commentType, address);
		assertEquals(commentValue, existingComment);
	}

	private void assertCommentDoesNotExists(String comment) {
		Memory memory = program.getMemory();
		Iterator<Address> addressIterator = listing.getCommentAddressIterator(memory, true);
		boolean commentExists = false;

		while (addressIterator.hasNext()) {
			Address address = addressIterator.next();
			for (int i : COMMENT_TYPES) {
				String foundComment = listing.getComment(i, address);
				if (foundComment != null && foundComment.equals(comment)) {
					commentExists = true;
				}
			}
		}

		assertFalse(commentExists);
	}
}
