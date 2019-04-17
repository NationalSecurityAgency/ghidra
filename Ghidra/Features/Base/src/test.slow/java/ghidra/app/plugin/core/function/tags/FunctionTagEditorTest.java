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

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.textfield.HintTextField;
import ghidra.app.cmd.function.ChangeFunctionTagCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.function.FunctionDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;
import ghidra.util.exception.UsrException;

/**
 * Test class for the {@link FunctionTagPlugin}. This tests the ability to use the
 * function tag edit GUI ({@link FunctionTagsComponentProvider} to create/edit/delete
 * tags.
 *
 * Test related to the merging and diffing of tags are defined in the
 * {@link FunctionTagMergeTest} class.
 */
public class FunctionTagEditorTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private CodeBrowserPlugin cb;
	private FunctionTagPlugin plugin;

	// Menu item available on a function entry point that launches the
	// dialog.
	private DockingActionIf editFunctionTags;

	private static final int DIALOG_WAIT_TIME = 3000;

	// Define addresses for the first two functions in the test program;
	// these will handle most cases we need to test.
	private Address NON_FUNCTION_ADDRESS;
	private Address FUNCTION_ENTRY_ADDRESS;

	// The UI we're testing.
	private FunctionTagsComponentProvider provider = null;

	/****************************************************************************************
	 * SETUP/TEARDOWN
	 ****************************************************************************************/

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

		goToFunction(FUNCTION_ENTRY_ADDRESS);
		showDialog();
		waitForSwing();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	/****************************************************************************************
	 * TESTS
	 ****************************************************************************************/

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
		assertTrue(!editFunctionTags.isEnabledForContext(actionContext));

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
	 * 
	 * @throws UsrException if there's an error retrieving tag panel components
	 * @throws IOException if there's an error retrieving tags from the database
	 */
	@Test
	public void testDeleteImmutableTag() throws IOException, UsrException {

		FunctionTagList list = getTagListInPanel("sourcePanel");

		// Get an immutable tag from the source panel and set it to be selected. Verify that
		// the delete button is disabled.
		FunctionTagTemp immutableTag = getImmutableTag();
		assertTrue("Must have at least one immutable tag for this test", immutableTag != null);
		selectTagInList(immutableTag.getName(), list);
		waitForSwing();
		assertFalse(isButtonEnabled("deleteBtn"));

		// Create a new tag and add it to the selection, and verify that the delete
		// button is still disabled.
		String tagName = "TAG 1";
		createTag(tagName);
		waitForSwing();
		list.setSelectionInterval(0, list.getModel().getSize() - 1);
		waitForSwing();
		assertFalse(isButtonEnabled("deleteBtn"));

		// Select just the non-immutable tag and verify that the delete button is now
		// enabled.
		selectTagInList(tagName, list);
		waitForSwing();
		assertTrue(isButtonEnabled("deleteBtn"));
	}

	/**
	 * Verifies that we can delete a previously immutable tag once it has been assigned
	 * to a function.
	 * 
	 * @throws UsrException if there's an error retrieving tag panel components
	 * @throws IOException if there's an error retrieving tags from the database
	 */
	@Test
	public void testDeleteImmutableTagAfterUse() throws UsrException, IOException {

		FunctionTagList list = getTagListInPanel("targetPanel");

		// Get an immutable tag from the source panel.
		FunctionTagTemp tag = getImmutableTag();
		assertTrue("Must have at least one immutable tag for this test", tag != null);

		// Assign the tag to a function, select the tag in the target panel,
		// and verify that the delete button is enabled.
		addTagToFunction(tag.getName(), FUNCTION_ENTRY_ADDRESS);
		waitForSwing();

		boolean inList = isTagNameInList(tag.getName(), getAllTags());
		assertTrue(inList);

		selectTagInList(tag.getName(), list);
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
		assertTrue(!isTagNameInList(tagName1, tags));
		assertTrue(!isTagNameInList(tagName2, tags));
		assertTrue(!isTagNameInList(tagName3, tags));

		// Now add them.
		createTag(tagName1 + ", " + tagName2 + "    ,,         " + tagName3);

		// Check the database to verify that the tags were added correctly.
		tags = getAllTags();
		assertTrue(isTagNameInList(tagName1, tags));
		assertTrue(isTagNameInList(tagName2, tags));
		assertTrue(isTagNameInList(tagName3, tags));
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
		assertTrue(isTagNameInList(name, getAllTags()));

		deleteTag(name);
		assertTrue(!isTagNameInList(name, getAllTags()));
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
		assertTrue(isTagNameInList(oldName, getAllTags()));

		// Update the tag name.
		updateTagName(oldName, newName);

		// Verify that the old name is no longer in the db, but the new name is.
		assertTrue(!isTagNameInList(oldName, getAllTags()));
		assertTrue(isTagNameInList(newName, getAllTags()));
	}

	/**
	 * Tests that we can add a tag to a function.
	 *
	 * @throws UsrException if there's an error adding the tag from the function
	 */
	@Test
	public void testAddTagToFunction() throws UsrException {
		String name = "TEST";
		createTag(name);
		addTagToFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertTrue(isTagNameInList(name, getTagsForFunctionAt(FUNCTION_ENTRY_ADDRESS)));
	}

	/**
	 * Tests that we can remove a tag from a function.
	 *
	 * @throws UsrException if there's an error adding or removing the tag from the function
	 */
	@Test
	public void testRemoveTagFromFunction() throws UsrException {
		String name = "TEST";
		createTag(name);
		addTagToFunction(name, FUNCTION_ENTRY_ADDRESS);
		removeTagFromFunction(name, FUNCTION_ENTRY_ADDRESS);
		assertTrue(!isTagNameInList(name, getTagsForFunctionAt(FUNCTION_ENTRY_ADDRESS)));
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
		Command cmd =
			new ChangeFunctionTagCmd(oldName, newName, ChangeFunctionTagCmd.TAG_NAME_CHANGED);
		tool.execute(cmd, program);

	}

	/**
	 * Creates a new tag and adds it to a function.
	 *
	 * @param name the tag name to add
	 * @param address the function entry point
	 * @throws UsrException if there's an error retrieving the source panel instance
	 */
	private void addTagToFunction(String name, Address address) throws UsrException {

		cb.goTo(new ProgramLocation(program, address));
		waitForSwing();

		FunctionTagList list = getTagListInPanel("sourcePanel");
		selectTagInList(name, list);
		clickButtonByName("addBtn");
	}

	/**
	 * Removes a tag from a function.
	 *
	 * @param name the tag name to remove
	 * @param address the function entry point
	 * @throws UsrException if there's an error retrieving the target panel instance
	 */
	private void removeTagFromFunction(String name, Address address) throws UsrException {

		cb.goTo(new ProgramLocation(program, address));
		waitForSwing();

		FunctionTagList list = getTagListInPanel("targetPanel");
		selectTagInList(name, list);
		clickButtonByName("removeBtn");
	}

	/**
	 * Gets the instance of the tag list in the given panel.
	 *
	 * @param panelName the name of the panel to search
	 * @return the function tag list
	 * @throws UsrException if there's an error retrieving the panel or tag list instances
	 */
	private FunctionTagList getTagListInPanel(String panelName) throws UsrException {
		Object comp = getInstanceField(panelName, provider);
		if (comp == null) {
			throw new UsrException("Error getting targetPanel field in provider");
		}

		TagListPanel panel = (TagListPanel) comp;
		Object list = getInstanceField("list", panel);
		if (list == null) {
			throw new UsrException("Error getting list field in TargetTagsPanel");
		}

		FunctionTagList tagList = (FunctionTagList) list;
		return tagList;
	}

	/**
	 * Selects the item in the list with the given name.
	 *
	 * @param name the tag name to select
	 * @param list the list to search
	 * @throws UsrException if there's an error retrieving tag from the list
	 */
	private void selectTagInList(String name, FunctionTagList list) throws UsrException {
		FunctionTag tag = getListItemByName(name, list);
		if (tag == null) {
			throw new UsrException("Error retrieving tag with name: " + name);
		}
		list.setSelectedValue(tag, true);
		waitForSwing();
	}

	/**
	 * Clicks the button with the given name in the {@link FunctionTagButtonPanel}.
	 *
	 * @param name the button name
	 * @throws UsrException if there's an error retrieving the button panel instance
	 */
	private void clickButtonByName(String name) throws UsrException {
		Object buttonPanel = getInstanceField("buttonPanel", provider);
		if (buttonPanel == null) {
			throw new UsrException("Error getting button panel field in provider");
		}
		FunctionTagButtonPanel btnPanel = (FunctionTagButtonPanel) buttonPanel;
		pressButtonByName(btnPanel, name);
		waitForSwing();
	}

	/**
	 * Returns true if the button with the given name is enabled.
	 * 
	 * @param name the button name
	 * @return true if enabled
	 * @throws UsrException if there's an error retrieving the button panel instance
	 */
	private boolean isButtonEnabled(String name) throws UsrException {
		Object buttonPanel = getInstanceField("buttonPanel", provider);
		if (buttonPanel == null) {
			throw new UsrException("Error getting button panel field in provider");
		}
		FunctionTagButtonPanel btnPanel = (FunctionTagButtonPanel) buttonPanel;
		AbstractButton button = findAbstractButtonByName(btnPanel, name);
		return isEnabled(button);
	}

	/**
	 * Returns the list item (FunctionTag) that has the given tag name.
	 *
	 * @param name the tag name
	 * @param list the list to search
	 */
	private FunctionTag getListItemByName(String name, FunctionTagList list) {
		int count = list.getModel().getSize();
		for (int i = 0; i < count; i++) {
			FunctionTag tag = list.getModel().getElementAt(i);
			if (tag.getName().equals(name)) {
				return tag;
			}
		}

		return null;
	}

	/**
	 * Loads the notepad program.
	 *
	 * @throws Exception if there's an error creating the program builder
	 */
	private void loadProgram() throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	/**
	 * Displays the function tag dialog.
	 *
	 * @return the dialog component provider
	 */
	private void showDialog() {

		performAction(editFunctionTags, cb.getProvider(), false);
		provider = waitForComponentProvider(tool.getToolFrame(),
			FunctionTagsComponentProvider.class, DIALOG_WAIT_TIME);
		tool.showComponentProvider(provider, true);
	}

	/**
	 * Places the code browser cursor at the given function entry point.
	 *
	 * @param address entry point of a function
	 */
	private void goToFunction(Address address) {
		cb.goTo(new ProgramLocation(program, address));
		assertEquals(address, cb.getCurrentAddress());
	}

	/**
	 * Adds a tag to the database.
	 *
	 * @param name the name of the tag
	 */
	private void createTag(String name) {

		HintTextField inputField = (HintTextField) getInstanceField("tagInputTF", provider);
		setText(inputField, name);
		triggerEnter(inputField);

		waitForSwing();
	}

	/**
	 * Removes a tag from the database.
	 *
	 * @param name the name of the tag
	 * @throws IOException if there's an error retrieving tags from the database
	 */
	private void deleteTag(String name) throws IOException {

		FunctionTag tag = getTagForName(name, getAllTags());
		int transactionID = program.startTransaction("delete function tag");
		tag.delete();
		program.endTransaction(transactionID, true);

		waitForSwing();
	}

	/**
	 * Returns all tags assigned to a function.
	 *
	 * @param addr the function entry point
	 * @return set of tags or null if function not found
	 */
	private Set<FunctionTag> getTagsForFunctionAt(Address addr) {

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
	private FunctionTagTemp getImmutableTag() throws UsrException {

		FunctionTagList list = getTagListInPanel("sourcePanel");

		for (int i = 0; i < list.getModel().getSize(); i++) {
			FunctionTag tag = list.getModel().getElementAt(i);
			if (tag instanceof FunctionTagTemp) {
				return (FunctionTagTemp) tag;
			}
		}

		return null;
	}

	/**
	 * Returns all tags in the database.
	 *
	 * @return list of all tags in the database
	 */
	private Collection<? extends FunctionTag> getAllTags() {
		FunctionManagerDB functionManager = (FunctionManagerDB) program.getFunctionManager();
		return functionManager.getFunctionTagManager().getAllFunctionTags();
	}

	/**
	 * Returns true if a tag is in the given list.
	 *
	 * @param name the tag name to search for
	 * @param tags the list to inspect
	 * @return true if found
	 */
	private boolean isTagNameInList(String name, Collection<? extends FunctionTag> tags) {
		FunctionTag tag = getTagForName(name, tags);
		return tag != null;
	}

	/**
	 * Returns the {@link FunctionTag} object with the given name.
	 *
	 * @param name the tag name
	 * @param tags the list to inspect
	 * @return function tag, or null if not found
	 */
	private FunctionTag getTagForName(String name, Collection<? extends FunctionTag> tags) {
		for (FunctionTag tag : tags) {
			if (tag.getName().equals(name)) {
				return tag;
			}
		}

		return null;
	}
}
