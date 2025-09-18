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

		builder.createComment("0x01001000", "EOL Comment", CommentType.EOL);
		builder.createComment("0x01001100", "Pre Comment", CommentType.PRE);
		builder.createComment("0x01001200", "Post Comment", CommentType.POST);
		builder.createComment("0x01001300", "Plate Comment", CommentType.PLATE);
		builder.createComment("0x01001400", "Repeatable Comment", CommentType.REPEATABLE);
		builder.createComment("0x01001500", "EOL Comment Repeated", CommentType.EOL);
		builder.createComment("0x01001600", "EOL Comment Repeated", CommentType.EOL);
		builder.createComment("0x01001700", "Generic Comment Repeated", CommentType.EOL);
		builder.createComment("0x01001800", "Generic Comment Repeated", CommentType.PRE);
		builder.createComment("0x01001900", "Generic Comment Repeated", CommentType.POST);
		builder.createComment("0x01002000", "Generic Comment Repeated", CommentType.PLATE);
		builder.createComment("0x01002100", "Generic Comment Repeated", CommentType.REPEATABLE);

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

		assertCommentEquals(0x01001000, "EOL Comment", CommentType.EOL);

		respondToDialog("EOL Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001000, "New Value", CommentType.EOL);
	}

	@Test
	public void testReplacePreComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001100, "Pre Comment", CommentType.PRE);

		respondToDialog("Pre Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001100, "New Value", CommentType.PRE);
	}

	@Test
	public void testReplacePostComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001200, "Post Comment", CommentType.POST);

		respondToDialog("Post Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001200, "New Value", CommentType.POST);
	}

	@Test
	public void testReplacePlateComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001300, "Plate Comment", CommentType.PLATE);

		respondToDialog("Plate Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001300, "New Value", CommentType.PLATE);
	}

	@Test
	public void testReplaceRepeatableComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001400, "Repeatable Comment", CommentType.REPEATABLE);

		respondToDialog("Repeatable Comment", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001400, "New Value", CommentType.REPEATABLE);
	}

	@Test
	public void testReplaceMultipleCommentsSameType() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001500, "EOL Comment Repeated", CommentType.EOL);
		assertCommentEquals(0x01001600, "EOL Comment Repeated", CommentType.EOL);

		respondToDialog("EOL Comment Repeated", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001500, "New Value", CommentType.EOL);
		assertCommentEquals(0x01001600, "New Value", CommentType.EOL);
	}

	@Test
	public void testReplaceMultipleCommentsDifferentTypes() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001700, "Generic Comment Repeated", CommentType.EOL);
		assertCommentEquals(0x01001800, "Generic Comment Repeated", CommentType.PRE);
		assertCommentEquals(0x01001900, "Generic Comment Repeated", CommentType.POST);
		assertCommentEquals(0x01002000, "Generic Comment Repeated", CommentType.PLATE);
		assertCommentEquals(0x01002100, "Generic Comment Repeated", CommentType.REPEATABLE);

		respondToDialog("Generic Comment Repeated", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001700, "New Value", CommentType.EOL);
		assertCommentEquals(0x01001800, "New Value", CommentType.PRE);
		assertCommentEquals(0x01001900, "New Value", CommentType.POST);
		assertCommentEquals(0x01002000, "New Value", CommentType.PLATE);
		assertCommentEquals(0x01002100, "New Value", CommentType.REPEATABLE);
	}

	@Test
	public void testReplaceNonexistantComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		respondToDialog("This Value Does Not Exist", FIND_DIALOG_TITLE);
		respondToDialog("New Value", REPLACE_DIALOG_TITLE);

		assertCommentDoesNotExist("New Value");
	}

	@Test
	public void testReplacePartialComment() throws Exception {
		ScriptTaskListener scriptID = env.runScript(script);
		assertNotNull(scriptID);

		assertCommentEquals(0x01001000, "EOL Comment", CommentType.EOL);
		assertCommentEquals(0x01001100, "Pre Comment", CommentType.PRE);
		assertCommentEquals(0x01001200, "Post Comment", CommentType.POST);
		assertCommentEquals(0x01001300, "Plate Comment", CommentType.PLATE);
		assertCommentEquals(0x01001400, "Repeatable Comment", CommentType.REPEATABLE);

		respondToDialog("Comment", FIND_DIALOG_TITLE);
		respondToDialog("Test", REPLACE_DIALOG_TITLE);

		waitForScriptCompletion(scriptID, SCRIPT_TIMEOUT);
		assertCommentEquals(0x01001000, "EOL Test", CommentType.EOL);
		assertCommentEquals(0x01001100, "Pre Test", CommentType.PRE);
		assertCommentEquals(0x01001200, "Post Test", CommentType.POST);
		assertCommentEquals(0x01001300, "Plate Test", CommentType.PLATE);
		assertCommentEquals(0x01001400, "Repeatable Test", CommentType.REPEATABLE);
	}

	private void respondToDialog(String response, String titleValue) {
		JDialog askStringDialog = waitForJDialog(null, titleValue, 3000);
		JTextField textField = findComponent(askStringDialog, JTextField.class);
		setText(textField, response);
		pressButtonByText(askStringDialog, "OK");
	}

	private void assertCommentEquals(int commentAddress, String commentValue,
			CommentType commentType) {
		Address address = program.getMinAddress().getNewAddress(commentAddress);
		String existingComment = listing.getComment(commentType, address);
		assertEquals(commentValue, existingComment);
	}

	private void assertCommentDoesNotExist(String comment) {
		Memory memory = program.getMemory();
		Iterator<Address> addressIterator = listing.getCommentAddressIterator(memory, true);
		boolean commentExists = false;

		while (addressIterator.hasNext()) {
			Address address = addressIterator.next();
			for (CommentType type : CommentType.values()) {
				String foundComment = listing.getComment(type, address);
				if (foundComment != null && foundComment.equals(comment)) {
					commentExists = true;
				}
			}
		}

		assertFalse(commentExists);
	}
}
