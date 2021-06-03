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
package ghidra.app.plugin.core.function.tags;

import static org.junit.Assert.*;

import java.awt.Dimension;
import java.io.IOException;
import java.util.*;

import javax.swing.AbstractButton;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.textfield.HintTextField;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.exception.UsrException;

/**
 * Test class for the {@link FunctionTagPlugin}. This tests the ability to use the
 * function tag edit GUI ({@link FunctionTagProvider} to create/edit/delete
 * tags.
 *
 * Test related to the merging and diffing of tags are defined in the
 * {@link FunctionTagMergeTest} class.
 */
public class FunctionTagPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private CodeBrowserPlugin cb;
	private FunctionTagPlugin plugin;

	private DockingActionIf editFunctionTags;

	private Address NON_FUNCTION_ADDRESS;
	private Address FUNCTION_ENTRY_ADDRESS;
	private Address FUNCTION_ENTRY_ADDRESS_2;
	private Address FUNCTION_ENTRY_ADDRESS_3;

	private FunctionTagProvider provider = null;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(GoToServicePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(FunctionTagPlugin.class.getName());

		cb = env.getPlugin(CodeBrowserPlugin.class);
		plugin = getPlugin(tool, FunctionTagPlugin.class);

		editFunctionTags = getAction(plugin, "Edit Function Tags");

		env.showTool();
		env.getTool().getToolFrame().setSize(new Dimension(1024, 768));
		waitForSwing();

		loadProgram();

		NON_FUNCTION_ADDRESS = addr("010022b8");
		FUNCTION_ENTRY_ADDRESS = addr("01002239");
		FUNCTION_ENTRY_ADDRESS_2 = addr("0100248f");
		FUNCTION_ENTRY_ADDRESS_3 = addr("0100299e");

		goToFunction(FUNCTION_ENTRY_ADDRESS);
		showDialog();
		waitForSwing();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	/**
	 * Tests that the menu option for bringing up the editor exists
	 * on function headers only.
	 */
	@Test
	public void testMenuOptionAvailability() {

		env.showTool();
		waitForSwing();

		cb.goTo(new ProgramLocation(program, NON_FUNCTION_ADDRESS));
		assertEquals(NON_FUNCTION_ADDRESS, cb.getCurrentAddress());
		ActionContext actionContext = cb.getProvider().getActionContext(null);
		assertFalse(editFunctionTags.isEnabledForContext(actionContext));

		cb.goToField(FUNCTION_ENTRY_ADDRESS, "Function Signature", 0, 0);
		assertEquals(FUNCTION_ENTRY_ADDRESS, cb.getCurrentAddress());
		actionContext = cb.getProvider().getActionContext(null);
		assertTrue(editFunctionTags.isEnabledForContext(actionContext));
	}

	/**
	 * Verify that the user cannot delete an immutable tag (a tag that has been preloaded
	 * from a configuration file). 
	 * <p>
	 * Secondary checks: 
	 * <li>Verify that the delete button will still be disabled if we add
	 * non-immutable tags to the selection</li>
	 * <li>Verify that the delete button will become enabled if we 
	 * remove any immutable tags from the selection</li>
	 * @throws Exception if there is a problem selecting tags
	 */
	@Test
	public void testDeleteImmutableTag() throws Exception {

		FunctionTagTable table = getSourceTable();

		// Get an immutable tag from the source panel and set it to be selected. Verify that
		// the delete button is disabled.
		InMemoryFunctionTag immutableTag = getImmutableTag();
		assertTrue("Must have at least one immutable tag for this test", immutableTag != null);
		selectTagInTable(immutableTag.getName(), table);
		waitForSwing();
		assertFalse(isButtonEnabled("deleteBtn"));

		// Create a new tag and add it to the selection, and verify that the delete
		// button is still disabled.
		String tagName = "TAG 1";
		createTag(tagName);
		waitForSwing();
		table.addRowSelectionInterval(0, table.getRowCount() - 1);
		waitForSwing();
		assertFalse(isButtonEnabled("deleteBtn"));

		// Select just the non-immutable tag and verify that the delete button is now
		// enabled.
		selectTagInTable(tagName, table);
		waitForSwing();
		assertTrue(isButtonEnabled("deleteBtn"));
	}

	/**
	 * Verifies that we can delete a previously immutable tag once it has been assigned
	 * to a function.
	 * @throws Exception if there is a problem adding tags to functions
	 */
	@Test
	public void testDeleteImmutableTagAfterUse() throws Exception {

		FunctionTagTable table = getTargetTable();

		// Get an immutable tag from the source panel.
		InMemoryFunctionTag tag = getImmutableTag();
		assertTrue("Must have at least one immutable tag for this test", tag != null);

		// Assign the tag to a function, select the tag in the target panel,
		// and verify that the delete button is enabled.
		addTagToFunction(tag.getName(), FUNCTION_ENTRY_ADDRESS);
		waitForSwing();

		boolean inList = tagExists(tag.getName(), getAllTags());
		assertTrue(inList);

		selectTagInTable(tag.getName(), table);
		waitForSwing();
		assertTrue(isButtonEnabled("deleteBtn"));
	}

	/**
	 * Tests that a new tag can be created.
	 *
	 * Note: This also tests the ability to input multiple entries at one time, with
	 * some questionable input (ie: empty entries that should be filtered out).
	 *
	 * @throws IOException if there's an error retrieving tags from the database
	 */
	@Test
	public void testCreateTag() throws IOException {

		// The tag names to add.
		String tagName1 = "TAG 1";
		String tagName2 = "TAG2";
		String tagName3 = "tag name 3";

		// First verify that our function does not already contain the tags we're going
		// to add.
		Collection<? extends FunctionTag> tags = getAllTags();
		assertFalse(tagExists(tagName1, tags));
		assertFalse(tagExists(tagName2, tags));
		assertFalse(tagExists(tagName3, tags));

		// Now add them.
		createTag(tagName1 + ", " + tagName2 + "    ,,         " + tagName3);

		// Check the database to verify that the tags were added correctly.
		tags = getAllTags();
		assertTrue(tagExists(tagName1, tags));
		assertTrue(tagExists(tagName2, tags));
		assertTrue(tagExists(tagName3, tags));
	}

	/**
	 * Tests that a tag can be deleted.
	 *
	 * @throws Exception if there's an error retrieving tags from the database
	 */
	@Test
	public void testDeleteTag() throws Exception {

		String name = "TEST";

		// First add a tag (so we have something to delete).
		createTag(name);
		assertTrue(tagExists(name, getAllTags()));

		deleteTag(name);
		assertFalse(tagExists(name, getAllTags()));
	}

	/**
	 * Tests that a tag name can be edited.
	 *
	 * @throws IOException if there's an error retrieving tags from the database
	 */
	@Test
	public void testEditTagName() throws IOException {

		String oldName = "TEST";
		String newName = "TEST-EDIT";

		// Add a tag and verify that it was correctly added to the database.
		createTag(oldName);
		assertTrue(tagExists(oldName, getAllTags()));

		// Update the tag name.
		updateTagName(oldName, newName);

		// Verify that the old name is no longer in the db, but the new name is.
		assertFalse(tagExists(oldName, getAllTags()));
		assertTrue(tagExists(newName, getAllTags()));
	}

	/**
	 * Tests that we can add a tag to a function.
	 * 
	 * @throws Exception if there is a problem adding tags to functions
	 */
	@Test
	public void testAddTagToFunction() throws Exception {
		String name = "TEST";
		createTag(name);
		addTagToFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertTrue(tagExists(name, getTags(FUNCTION_ENTRY_ADDRESS)));
	}

	/**
	 * Tests that we can remove a tag from a function.
	 * @throws Exception if there is a problem adding/removing tags to functions
	 */
	@Test
	public void testRemoveTagFromFunction() throws Exception {
		String name = "TEST";
		createTag(name);
		addTagToFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertTableTagCount(name, 1);
		removeTagFromFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertFalse(tagExists(name, getTags(FUNCTION_ENTRY_ADDRESS)));
		assertTableTagCount(name, 0);
	}

	@Test
	public void testFunctionRemoved() throws Exception {
		String name = "TEST";
		createTag(name);
		addTagToFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertTableTagCount(name, 1);

		removeFunction(FUNCTION_ENTRY_ADDRESS);
		assertTrue(tagExists(name, getAllTags()));
		assertTableTagCount(name, 0);
	}

	/**
	 * Verifies that the tags assigned to a function are visible in the function tag
	 * panel
	 * @throws Exception if there is a problem adding tags to functions
	 */
	@Test
	public void testViewFunctionsForTag() throws Exception {

		// Verify that the function panel is initially empty
		AllFunctionsPanel functionsPanel = provider.getAllFunctionsPanel();
		List<Function> functions = functionsPanel.getFunctions();
		assertTrue(functions.isEmpty());

		// Create a new tag and add it to a function
		String tagName1 = "TAG 1";
		createTag(tagName1);
		addTagToFunction(tagName1, FUNCTION_ENTRY_ADDRESS);

		// Select the tag in the target panel
		FunctionTagTable table = getTargetTable();
		selectTagInTable(tagName1, table);
		waitForTableModel(functionsPanel.getTableModel());

		// Verify that the function is shown in the function panel (check that
		// we have exactly 1 match, and that the address is for the correct
		// function)
		functions = functionsPanel.getFunctions();
		assertTrue(functions.size() == 1);
		Function f = functions.get(0);
		assertTrue(f.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS));
	}

	/**
	 * Verifies if a tag is assigned to multiple functions they will all be shown
	 * in the function panel
	 * 
	 * @throws Exception if there's a problem adding tags to functions
	 */
	@Test
	public void testMultipleFunctionsWithTag() throws Exception {

		// Verify that the function panel is initially empty
		AllFunctionsPanel functionsPanel = provider.getAllFunctionsPanel();
		List<Function> functions = functionsPanel.getFunctions();
		assertTrue(functions.isEmpty());

		// Create a new tag and add it to both functions
		String tagName1 = "TAG 1";
		createTag(tagName1);
		addTagToFunction(tagName1, FUNCTION_ENTRY_ADDRESS);
		addTagToFunction(tagName1, FUNCTION_ENTRY_ADDRESS_2);

		// Select the tag in the target panel
		FunctionTagTable table = getTargetTable();
		selectTagInTable(tagName1, table);
		waitForTableModel(functionsPanel.getTableModel());

		// Verify that both functions are shown in the function panel (check that
		// we have exactly 2 matches, and that the addresses are for the correct
		// functions)
		functions = functionsPanel.getFunctions();
		assertTrue(functions.size() == 2);
		Function f1 = functions.get(0);
		Function f2 = functions.get(1);
		assertTrue(f1.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS));
		assertTrue(f2.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS_2));
	}

	/**
	 * Verifies if multiple tags are selected, all functions containing that tag
	 * are displayed
	 * 
	 * @throws Exception if there's a problem adding tags to functions
	 */
	@Test
	public void testViewMultipleFunctions() throws Exception {

		// Verify that the function panel is initially empty
		AllFunctionsPanel functionsPanel = provider.getAllFunctionsPanel();
		List<Function> functions = functionsPanel.getFunctions();
		assertTrue(functions.isEmpty());

		// Create two new tags and add them to the functions
		String tagName1 = "TAG 1";
		createTag(tagName1);
		addTagToFunction(tagName1, FUNCTION_ENTRY_ADDRESS);

		String tagName2 = "TAG 2";
		createTag(tagName2);
		addTagToFunction(tagName2, FUNCTION_ENTRY_ADDRESS_2);
		addTagToFunction(tagName2, FUNCTION_ENTRY_ADDRESS_3);

		// Select both tags and verify that 3 functions are listed in 
		// the functions panel
		goTo(tool, program, addr("00000000"));
		FunctionTagTable table = getSourceTable();
		selectTagInTable(tagName1, table);
		int index = table.getSelectedRow();
		table.addRowSelectionInterval(index, index + 1);
		clickTableRange(table, index, 2);

		waitForTableModel(functionsPanel.getTableModel());

		// Verify that all 3 functions are in the function panel
		functions = functionsPanel.getFunctions();
		assertTrue(functions.size() == 3);
		Function f1 = functions.get(0);
		Function f2 = functions.get(1);
		Function f3 = functions.get(2);
		assertTrue(f1.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS));
		assertTrue(f2.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS_2));
		assertTrue(f3.getEntryPoint().equals(FUNCTION_ENTRY_ADDRESS_3));
	}

	/****************************************************************************************
	 * PRIVATE METHODS
	 ****************************************************************************************/

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	/**
	 * Updates the name of a tag in the model.
	 *
	 * @param oldName the current tag name
	 * @param newName the new tag name
	 */
	private void updateTagName(String oldName, String newName) {

		int row = getRow(oldName);
		SourceTagsPanel sourcePanel = provider.getSourcePanel();
		runSwing(() -> sourcePanel.editRow(row), false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		runSwing(() -> {
			dialog.setValue(newName, 0);
			dialog.setValue("Some new comment", 1);
		});
		pressButtonByText(dialog, "OK");
		waitForSwing();
	}

	private int getRow(String tagName) {
		SourceTagsPanel sourcePanel = provider.getSourcePanel();
		FunctionTagTableModel model = sourcePanel.getModel();
		int n = model.getRowCount();
		for (int row = 0; row < n; row++) {
			FunctionTagRowObject rowObject = model.getRowObject(row);
			if (rowObject.getName().equals(tagName)) {
				return row;
			}
		}

		fail("Could not find row for '" + tagName + "'");
		return -1;
	}

	/**
	 * Creates a new tag and adds it to a function.
	 *
	 * @param name the tag name to add
	 * @param address the function entry point
	 * @throws Exception if there is a problem selecting tags or clicking buttons
	 */
	private void addTagToFunction(String name, Address address) throws Exception {

		cb.goTo(new ProgramLocation(program, address));
		waitForSwing();

		FunctionTagTable list = getSourceTable();
		selectTagInTable(name, list);

		clickButton("addBtn");
	}

	/**
	 * Removes a tag from a function.
	 *
	 * @param name the tag name to remove
	 * @param address the function entry point
	 * @throws Exception if there is a problem selecting tags or clicking buttons
	 */
	private void removeTagFromFunction(String name, Address address) throws Exception {

		cb.goTo(new ProgramLocation(program, address));
		waitForSwing();

		FunctionTagTable table = getTargetTable();
		selectTagInTable(name, table);
		clickButton("removeBtn");
	}

	private void removeFunction(Address address) {
		applyCmd(program, new DeleteFunctionCmd(address));
	}

	private FunctionTagTable getTargetTable() {
		waitForTables();
		return provider.getTargetPanel().getTable();
	}

	private FunctionTagTable getSourceTable() {
		waitForTables();
		return provider.getSourcePanel().getTable();
	}

	/**
	 * Selects the item in the table with the given name.
	 *
	 * @param name the tag name to select
	 * @param table the table to search
	 * @throws Exception if there is a problem clicking cells in a list
	 */
	private void selectTagInTable(String name, FunctionTagTable table) throws Exception {
		assertTagExists(name, table);

		int row = 0;
		for (int i = 0; i < table.getRowCount(); i++) {
			String tagname = (String) table.getValueAt(i, 0);
			if (tagname.equals(name)) {
				table.addRowSelectionInterval(i, i);
				row = i;
			}
		}

		clickTableCell(table, row, 0, 1);
		waitForSwing();
	}

	/**
	 * Clicks the button with the given name in the {@link FunctionTagButtonPanel}.
	 *
	 * @param name the button name
	 */
	private void clickButton(String name) {
		FunctionTagButtonPanel btnPanel = provider.getButtonPanel();

		// if we try to press a button before the panel is showing, the test will fail
		waitFor(btnPanel::isShowing);
		pressButtonByName(btnPanel, name);
		waitForSwing();
	}

	/**
	 * Returns true if the button with the given name is enabled.
	 * 
	 * @param name the button name
	 * @return true if enabled
	 */
	private boolean isButtonEnabled(String name) {
		FunctionTagButtonPanel btnPanel = provider.getButtonPanel();
		AbstractButton button = findAbstractButtonByName(btnPanel, name);
		return isEnabled(button);
	}

	private FunctionTag assertTagExists(String name, FunctionTagTable table) {
		int rows = table.getRowCount();
		for (int row = 0; row < rows; row++) {
			FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
			FunctionTagRowObject rowObject = model.getRowObject(row);
			if (rowObject.getName().equals(name)) {
				return rowObject.getTag();
			}
		}

		fail("Error retrieving tag with name: " + name);
		return null;
	}

	private void assertTableTagCount(String name, int expected) {

		waitForSwing();
		FunctionTagTableModel model = provider.getSourcePanel().getModel();
		waitForTableModel(model);

		FunctionTagRowObject rowObject = model.getRowObject(name);
		assertNotNull(rowObject);
		assertEquals("Tag count in table is incorrect", expected, rowObject.getCount());
	}

	private void loadProgram() throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	private void showDialog() {
		performAction(editFunctionTags, cb.getProvider(), false);
		provider = waitForComponentProvider(FunctionTagProvider.class);
		tool.showComponentProvider(provider, true);
	}

	private void goToFunction(Address address) {
		cb.goTo(new ProgramLocation(program, address));
		assertEquals(address, cb.getCurrentAddress());
	}

	private void createTag(String nameList) {

		HintTextField inputField = provider.getTagInputField();
		setText(inputField, nameList);
		provider.pressEnterOnTagInputField();
		waitForTasks();
		waitForTables();

		Collection<? extends FunctionTag> tags = getAllTags();
		String[] parts = nameList.split(",");
		for (String name : parts) {
			if (StringUtils.isBlank(name)) {
				continue;
			}
			name = name.trim();
			assertTrue("Tag not created '" + name + "' from text '" + nameList + "'",
				tagExists(name.trim(), tags));
		}
	}

	private void waitForTables() {
		TargetTagsPanel targetPanel = provider.getTargetPanel();
		SourceTagsPanel sourcePanel = provider.getSourcePanel();
		FunctionTagTableModel tmodel = targetPanel.getModel();
		FunctionTagTableModel smodel = sourcePanel.getModel();
		waitForTableModel(tmodel);
		waitForTableModel(smodel);
		waitForSwing();
	}

	private void deleteTag(String name) {

		FunctionTag tag = getTagForName(name, getAllTags());
		tx(program, () -> tag.delete());
		waitForTables();
	}

	/**
	 * Returns all tags assigned to a function.
	 *
	 * @param addr the function entry point
	 * @return set of tags or null if function not found
	 */
	private Set<FunctionTag> getTags(Address addr) {

		FunctionDB function = (FunctionDB) program.getFunctionManager().getFunctionContaining(addr);
		if (function == null) {
			return null;
		}

		Set<FunctionTag> tagSet = new HashSet<>();
		Collection<FunctionTag> tags;
		tags = function.getTags();
		for (FunctionTag tag : tags) {
			tagSet.add(tag);
		}

		return tagSet;
	}

	/**
	 * Returns an immutable tag (the first one found) from the source panel, if one exists. 
	 * 
	 * @return an immutable tag, or null if not found
	 * @throws UsrException if there's an error retrieving tags in the source panel
	 */
	private InMemoryFunctionTag getImmutableTag() throws UsrException {

		FunctionTagTable table = getSourceTable();
		FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
		Optional<FunctionTagRowObject> optional = model.getModelData()
				.stream()
				.filter(row -> row.isImmutable())
				.findAny();
		assertTrue("No Immutable tags found", optional.isPresent());
		FunctionTag foundTag = optional.get().getTag();
		return (InMemoryFunctionTag) foundTag;
	}

	private Collection<? extends FunctionTag> getAllTags() {
		return provider.backgroundLoadTags();
	}

	private boolean tagExists(String name, Collection<? extends FunctionTag> tags) {
		FunctionTag tag = getTagForName(name, tags);
		return tag != null;
	}

	private FunctionTag getTagForName(String name, Collection<? extends FunctionTag> tags) {
		for (FunctionTag tag : tags) {
			if (tag.getName().equals(name)) {
				return tag;
			}
		}

		return null;
	}
}
