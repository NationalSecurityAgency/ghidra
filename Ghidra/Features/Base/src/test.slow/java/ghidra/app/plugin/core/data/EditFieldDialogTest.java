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
package ghidra.app.plugin.core.data;

import static org.junit.Assert.*;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.test.*;

public class EditFieldDialogTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private DockingActionIf editFieldAction;
	private EditDataFieldDialog dialog;
	private CodeBrowserPlugin codeBrowser;
	private Structure structure;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		DataPlugin plugin = getPlugin(tool, DataPlugin.class);
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);

		program = buildProgram();
		env.open(program);
		env.showTool();
		editFieldAction = getAction(plugin, "Edit Field");
		Data dataAt = program.getListing().getDataAt(addr(0x100));
		structure = (Structure) dataAt.getDataType();
		codeBrowser.toggleOpen(dataAt);
		waitForSwing();
	}

	private Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", true);
		builder.createMemory("Test", "0", 1000);
		StructureDataType struct = new StructureDataType("TestStruct", 4);
		struct.add(new WordDataType(), "count", "This is the count field");
		struct.add(new WordDataType(), "color", "This is the color field");
		builder.applyDataType("0x100", struct);
		return builder.getProgram();

	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testEditDefinedFieldName() {
		goTo(0x104);
		showFieldEditDialog();
		assertEquals("count", structure.getComponent(4).getFieldName());
		assertEquals("count", getNameText());

		setNameText("weight");

		pressOk();
		waitForTasks();
		assertEquals("weight", structure.getComponent(4).getFieldName());
	}

	@Test
	public void testEditDefinedFieldComment() {
		goTo(0x104);
		showFieldEditDialog();
		assertEquals("This is the count field", structure.getComponent(4).getComment());
		assertEquals("This is the count field", getCommentText());

		setCommentText("This is the weight field");

		pressOk();
		waitForTasks();
		assertEquals("This is the weight field", structure.getComponent(4).getComment());
	}

	@Test
	public void testEditDefinedFieldDataType() {
		goTo(0x104);
		showFieldEditDialog();
		assertEquals("word", structure.getComponent(4).getDataType().getDisplayName());
		assertEquals("word", getDataTypeText());

		setDataType(new CharDataType());

		pressOk();

		waitForTasks();
		assertFalse(isDialogVisible());

		assertEquals("char", structure.getComponent(4).getDataType().getDisplayName());
	}

	@Test
	public void testEditUndefinedFieldName() {
		goTo(0x101);
		showFieldEditDialog();
		assertNull(structure.getComponent(1).getFieldName());
		assertEquals("", getNameText());

		setNameText("abc");

		pressOk();
		waitForTasks();
		assertEquals("abc", structure.getComponent(1).getFieldName());
		assertEquals("undefined1", structure.getComponent(1).getDataType().getDisplayName());
	}

	@Test
	public void testEditUndefinedComment() {
		goTo(0x101);
		showFieldEditDialog();
		assertNull(structure.getComponent(1).getComment());
		assertEquals("", getCommentText());

		setCommentText("comment");

		pressOk();
		waitForTasks();
		assertEquals("comment", structure.getComponent(1).getComment());
		assertEquals("undefined1", structure.getComponent(1).getDataType().getDisplayName());
	}

	@Test
	public void testEditUndefinedDataType() {
		goTo(0x101);
		showFieldEditDialog();
		assertNull(structure.getComponent(1).getComment());
		assertEquals("undefined", getDataTypeText());

		setDataType(new ByteDataType());

		pressOk();
		waitForTasks();
		assertEquals("byte", structure.getComponent(1).getDataType().getDisplayName());
	}

	private boolean isDialogVisible() {
		return runSwing(() -> dialog.isVisible());
	}

	private void showFieldEditDialog() {
		performAction(editFieldAction, false);
		dialog = waitForDialogComponent(EditDataFieldDialog.class);
	}

	private void goTo(long addressOffset) {
		Address address = addr(addressOffset);
		codeBrowser.goToField(address, "Address", 0, 0);
		waitForSwing();
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void pressOk() {
		runSwing(() -> dialog.okCallback());
	}

	private String getNameText() {
		return runSwing(() -> dialog.getNameText());
	}

	private void setNameText(String newName) {
		runSwing(() -> dialog.setNameText(newName));
	}

	private String getCommentText() {
		return runSwing(() -> dialog.getCommentText());
	}

	private void setCommentText(String newComment) {
		runSwing(() -> dialog.setCommentText(newComment));
	}

	private String getDataTypeText() {
		return runSwing(() -> dialog.getDataTypeText());
	}

	private void setDataType(DataType dataType) {
		runSwing(() -> dialog.setDataType(dataType));
	}

	private String getDialogStatusText() {
		return runSwing(() -> dialog.getStatusText());
	}
}
