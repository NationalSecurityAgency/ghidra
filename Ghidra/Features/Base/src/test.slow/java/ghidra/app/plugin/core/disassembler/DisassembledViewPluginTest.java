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
package ghidra.app.plugin.core.disassembler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.awt.Color;
import java.awt.Font;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JList;
import javax.swing.ListModel;

import org.junit.*;

import docking.ComponentProvider;
import docking.widgets.fieldpanel.FieldPanel;
import ghidra.GhidraOptions;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;

public class DisassembledViewPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private ComponentProvider componentProvider;
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private ProgramPlugin plugin;

	public DisassembledViewPluginTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DisassembledViewPlugin.class.getName());

		plugin = env.getPlugin(DisassembledViewPlugin.class);
		componentProvider = (ComponentProvider) getInstanceField("displayComponent", plugin);
	}

	@After
	public void tearDown() throws Exception {

		if (program != null) {
			env.release(program);
		}
		env.dispose();
		env = null;
	}

	/**
	 * Tests the plugins response to 
	 * {@link ghidra.app.events.ProgramLocationPluginEvent}s.  This plugin is
	 * driven off of these events.
	 * 
	 * @throws Exception If there is a problem opening the program.
	 */
	@Test
	public void testProcessingOnLocationChanged() throws Exception {
		openProgram("notepad");

		// get the list hiding inside of the component provider
		JList list = (JList) getInstanceField("contentList", componentProvider);

		// sanity check
		assertEquals("The component provider has data when it is not visible.", 0,
			list.getModel().getSize());

		// show the plugin and make sure it is visible before we continue
		tool.showComponentProvider(componentProvider, true);
		waitForPostedSwingRunnables();

		ListModel modelOne = list.getModel();

		// now the list should have data, as it will populate itself off of the
		// current program location of the plugin
		assertTrue("The component provider does not have data when it " + "should.",
			(modelOne.getSize() != 0));

		// make sure we process the event in order to show the user the 
		// preview
		CodeBrowserPlugin cbPlugin = getPlugin(tool, CodeBrowserPlugin.class);

		// scroll the display and force a new selection
		pageDown(cbPlugin.getFieldPanel());
		simulateButtonPress(cbPlugin);
		waitForPostedSwingRunnables();

		// get the data
		ListModel modelTwo = list.getModel();

		boolean sameData = compareListData(modelOne, modelTwo);
		assertTrue("The contents of the two lists are the same when they " + "should not be.",
			!sameData);

		// make sure no work is done when we are not visible
		tool.showComponentProvider(componentProvider, false);
		waitForPostedSwingRunnables();

		assertEquals("The component provider has data when it is not visible.", 0,
			list.getModel().getSize());

		// show the plugin so that it will get the program location change 
		// data
		tool.showComponentProvider(componentProvider, true);
		waitForPostedSwingRunnables();

		// test that sending a bad address will not return any results or 
		// throw any exceptions
		Memory memory = program.getMemory();
		MemoryBlock textBlock = memory.getBlock(".text");
		Address endAddress = textBlock.getEnd();

		// creating a program location based upon the end address should result
		// in only one item in the disassembled list
		ProgramLocation location = new ProgramLocation(program, endAddress);

		// call the locationChanged() method
		invokeInstanceMethod("locationChanged", plugin, new Class[] { ProgramLocation.class },
			new Object[] { location });

		assertTrue(
			"The plugin's display list has more than 1 element when " +
				"at the end address of a memory block.  List size: " + list.getModel().getSize(),
			(list.getModel().getSize() == 1));

		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(endAddress);
		Address invalidAddress = endAddress.addNoWrap(codeUnit.getLength());
		ProgramLocation newLocation = new ProgramLocation(program, invalidAddress);

		invokeInstanceMethod("locationChanged", plugin, new Class[] { ProgramLocation.class },
			new Object[] { newLocation });

		assertEquals("The plugin's display list has data when there is an " +
			"invalid address at the current program location.", list.getModel().getSize(), 0);
	}

	/**
	 * Tests the plugins response to {@link ProgramSelectionPluginEvent}s.
	 * 
	 * @throws Exception If there is a problem opening the program.
	 */
	@Test
	public void testProcessingOnSelectionChanged() throws Exception {
		openProgram("notepad");

		tool.showComponentProvider(componentProvider, true);
		waitForPostedSwingRunnables();

		// the Java component that is our display for the plugin
		JList list = (JList) getInstanceField("contentList", componentProvider);
		ListModel listContents = list.getModel();

		// make sure that nothing happens on a single-selection     
		plugin.processEvent(createProgramSelectionEvent(false));

		assertTrue("The list is not the same after processing a " + "single-selection event.",
			compareListData(listContents, list.getModel()));

		// make sure that the component display is cleared when there is a 
		// multiple-selection
		plugin.processEvent(createProgramSelectionEvent(true));

		assertTrue(
			"The list content did not change after processing a " + "multiple-selection event.",
			!compareListData(listContents, list.getModel()));
	}

	/**
	 * Tests the plugin's response to changes in the user display preferences
	 * as they are changed in the Options for the code browser.
	 * 
	 * @throws Exception If there is a problem opening the program.
	 */
	@Test
	public void testDisplayConfiguration() throws Exception {
		// test that the display characteristics change with the Options
		// values

		openProgram("notepad");

		tool.showComponentProvider(componentProvider, true);
		waitForPostedSwingRunnables();

		String[] fieldNames =
			{ "selectedAddressColor", "addressForegroundColor", "backgroundColor", "font" };

		// get the current display options
		Map<String, Object> optionsMap = new HashMap<>();

		for (String fieldName : fieldNames) {
			optionsMap.put(fieldName, getInstanceField(fieldName, componentProvider));
		}

		// change the global options for the plugin's display options
		Options opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);

		// get and change each options of interest
		String optionToChange = GhidraOptions.OPTION_SELECTION_COLOR;
		Color currentColor =
			opt.getColor(optionToChange, (Color) optionsMap.get("selectedAddressColor"));
		opt.setColor(optionToChange, deriveNewColor(currentColor));

		// the rest of the options to change are stored under a different
		// options node
		opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);

		optionToChange = (String) getInstanceField("ADDRESS_COLOR_OPTION", componentProvider);
		currentColor =
			opt.getColor(optionToChange, (Color) optionsMap.get("addressForegroundColor"));
		opt.setColor(optionToChange, deriveNewColor(currentColor));

		optionToChange = (String) getInstanceField("BACKGROUND_COLOR_OPTION", componentProvider);
		currentColor = opt.getColor(optionToChange, (Color) optionsMap.get("backgroundColor"));
		opt.setColor(optionToChange, deriveNewColor(currentColor));

		optionToChange = (String) getInstanceField("ADDRESS_FONT_OPTION", componentProvider);
		Font currentFont = opt.getFont(optionToChange, (Font) optionsMap.get("font"));
		opt.setFont(optionToChange, currentFont.deriveFont((float) currentFont.getSize() + 1));

		// now make sure that the changes have been propogated
		for (int i = 0; i < fieldNames.length; i++) {

			Object newValue = getInstanceField(fieldNames[i], componentProvider);

			assertTrue("The old value has not changed in response to " +
				"changing the options.  Value: " + fieldNames[i],
				!(newValue.equals(optionsMap.get(fieldNames[i]))));
		}
	}

	/**
	 * Creates a {@link ProgramSelectionPluginEvent} to simulate selecting a
	 * single address or multiple addresses in the code browser plugin.
	 * 
	 * @param  multiSelection True creates an event for multiple selections.
	 * @return The created event.
	 */
	private PluginEvent createProgramSelectionEvent(boolean multiSelection) {
		ProgramLocation programLoc = plugin.getProgramLocation();
		Address currentAddress = programLoc.getAddress();
		Address nextAddress = currentAddress;

		if (multiSelection) {
			nextAddress = currentAddress.next();
		}

		ProgramSelection selection = new ProgramSelection(currentAddress, nextAddress);
		return new ProgramSelectionPluginEvent("CodeBrowserPlugin", selection, program);
	}

	/**
	 * Creates a new Color object that is different than the one provided.
	 * 
	 * @param  originalColor The color from which the new Color will be 
	 *         derived.
	 * @return A new color that is different than the one given.
	 */
	public Color deriveNewColor(Color originalColor) {
		Color newColor = null;

		if (originalColor == Color.BLACK) {
			newColor = originalColor.brighter();
		}
		else {
			newColor = originalColor.darker();
		}

		return newColor;
	}

	/**
	 * Simulates a user click in the code browser plugin.
	 * 
	 * @param cbp The code browser plugin instance to click.
	 */
	private void simulateButtonPress(final CodeBrowserPlugin cbp) {
		runSwing(() -> click(cbp, 1));
	}

	/**
	 * Moves the code browser's display down a page, as if the user had 
	 * pressed the page down button.
	 * 
	 * @param fieldPanel The field panel display of the code browser.
	 */
	private void pageDown(final FieldPanel fieldPanel) {
		runSwing(() -> fieldPanel.pageDown());
	}

	/**
	 * Compares the two given lists based upon the contents being the same
	 * in terms of order and by comparing via the 
	 * {@link Object#equals(Object)} method.
	 * 
	 * @param  modelOne The first list contents to compare
	 * @param  modelTwo The second list contents to compare
	 * @return True if both lists hold the equal contents in the same order.
	 */
	private boolean compareListData(ListModel modelOne, ListModel modelTwo) {
		boolean isSame = false;

		if (modelOne.getSize() == modelTwo.getSize()) {
			// so far, so good...innocent until proven guilty
			isSame = true;

			for (int i = 0; (i < modelOne.getSize()) && isSame; i++) {
				if (modelOne.getElementAt(i) == null) {
					isSame = (modelTwo.getElementAt(i) == null);
				}
				else {
					isSame = (modelOne.getElementAt(i).equals(modelTwo.getElementAt(i)));
				}
			}
		}

		return isSame;
	}

	/**
	 * Opens the program of the given name and shows the tool with that
	 * program.
	 * 
	 * @param name
	 * @throws Exception
	 */
	private void openProgram(String name) throws Exception {

		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();

		env.showTool(program);
		waitForPostedSwingRunnables();
	}
}
