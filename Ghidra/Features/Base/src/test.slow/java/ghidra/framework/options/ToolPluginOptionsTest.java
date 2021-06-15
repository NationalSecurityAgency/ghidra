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
package ghidra.framework.options;

import static org.junit.Assert.*;

import java.awt.Color;
import java.io.File;
import java.util.*;

import javax.swing.KeyStroke;

import org.junit.*;

import generic.stl.Pair;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.plugin.core.searchtext.SearchTextPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * This test differs from {@link OptionsTest} in that this test is an integration test, pulling
 * options that have been registered by plugins.
 */
public class ToolPluginOptionsTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String NEW_TEST_OPTION_NAME = "NEW_TEST_OPTION_NAME";
	private static final String TEST_OPTION_STRING_VALUE = "TEST_OPTION_STRING_VALUE";

	private TestEnv env;
	private PluginTool tool;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		setUpSearchTool(tool);
	}

	private void setUpSearchTool(PluginTool tool) throws Exception {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(ProgramManagerPlugin.class.getName());
		tool.addPlugin(GoToServicePlugin.class.getName());
		tool.addPlugin(SearchTextPlugin.class.getName());

		showTool(tool);
	}

	@After
	public void tearDown() {
		env.closeTool(tool);
		env.dispose();
	}

	@Test
	public void testRestoreDefaults() {
		ToolOptions options = tool.getOptions("Search");

		//
		// Record the state of the original option
		//
		Map<String, Object> initialValues = new HashMap<>();
		List<String> optionNames = options.getOptionNames();
		for (String name : optionNames) {
			Object value = options.getObject(name, null);
			initialValues.put(name, value);
		}

		//
		// Change some values
		//
		String optionName = " Highlight Color";
		Color highlightColor = options.getColor(optionName, null);
		assertNotNull("Existing option has been removed--update test", highlightColor);
		options.setColor(optionName, Color.RED);

		optionName = "Highlight Search Results";
		boolean highlightResults = options.getBoolean(optionName, true);
		options.setBoolean(optionName, !highlightResults);

		optionName = "Search Limit";
		int searchLimit = options.getInt(optionName, 0);
		options.setInt(optionName, searchLimit + 100);

		//
		// Restore to default
		//
		options.restoreDefaultValues();

		//
		// Validate the current options against the saved options
		//
		Map<String, Object> latestValues = new HashMap<>();
		optionNames = options.getOptionNames();
		for (String name : optionNames) {
			Object value = options.getObject(name, null);
			latestValues.put(name, value);
		}

		List<String> diffs = getDiffs(initialValues, latestValues);

		if (diffs.size() != 0) {
			System.err.println(
				"Options values are not restored back to the original settings - diffs");
			for (String diff : diffs) {
				System.err.println("\tdiff: " + diff);
			}
			Assert.fail("Options values not restored (see error output)");
		}
	}

	@Test
	public void testOptionsWithoutRegisteredOwnerGoAway() {
		//
		// Test that an option value that is not set or read will disappear after saving the 
		// owning tool.
		//

		Options options = loadSearchOptions();

		Pair<String, String> changedOption = changeStringTestOption(options);

		//
		// See if the options are there again after saving and reloading.  They should be there, 
		// since the previous operation set the value.  We are careful here to simply check
		// for the options existence, but not to retrieve it, as doing so would trigger the 
		// option to be stored again.
		//
		options = saveAndLoadOptions();
		verifyStringOptionStillChanged_WithoutUsingOptionsAPI(options, changedOption.first);

		options = saveAndLoadOptions();
		verifyUnusedOptionNoLongerHasEntry(options, changedOption.first);
	}

	@Test
	public void testSaveOnlyNonDefaultOptions() {
		ToolOptions options = loadSearchOptions();
		options = saveAndLoadOptions();
		assertAllDefaultOptions(options);

		Pair<String, String> changedOption = changeStringTestOption(options);

		options = saveAndLoadOptions();
		assertOnlyNonDefaultOption(options, changedOption.first);

		options.restoreDefaultValues();

		options = loadSearchOptions();
		options = saveAndLoadOptions();
		assertAllDefaultOptions(options);
	}

	@Test
	public void testAccessingOptionsPreventsRemoval() {
		//
		// Repeatedly save/load options, accessing them each time, and make sure that they 
		// re-appear each load.
		//

		Options options = loadSearchOptions();

		Pair<String, String> changedOption = changeStringTestOption(options);

		options = saveAndLoadOptions();
		verifyStringOptionsStillChanged_UsingTheOptionsAPI(options, changedOption);

		options.registerOption(NEW_TEST_OPTION_NAME, "default", null, "description");
		options = saveAndLoadOptions();
		verifyStringOptionsStillChanged_UsingTheOptionsAPI(options, changedOption);

		options.registerOption(NEW_TEST_OPTION_NAME, "default", null, "description");
		options = saveAndLoadOptions();
		verifyStringOptionsStillChanged_UsingTheOptionsAPI(options, changedOption);

		//
		// now save twice in a row without accessing and the untouched option should be gone
		// 
		options = saveAndLoadOptions();
		options = saveAndLoadOptions();
		verifyUnusedOptionNoLongerHasEntry(options, changedOption.first);
	}

	@Test
	public void testClearingKeyBindingOption() {

		Options options = loadKeyBindingOptions();

		String optionName = clearKeyBinding(options);

		options = saveAndLoadOptions();
		verifyKeyBindingIsStillCleared(options, optionName);
	}

	@Test
	public void testAccessingOptionWithoutRegistering() {

		ToolOptions options = loadSearchOptions();
		String defaultValue = "default";
		Option option =
			options.getOption(NEW_TEST_OPTION_NAME, OptionType.STRING_TYPE, defaultValue);
		assertNotNull("unregistered option was not created on access", option);
		assertEquals(defaultValue, option.getValue(defaultValue));
	}

	@Test
	public void testSetFileOptionToNull() {
		// 
		// Make sure the user can set the file option to null, to allow the clearing of a value
		//

		Options options = loadSearchOptions();

		HelpLocation help = null;
		File defaultValue = null;
		String optionName = "Foo File";
		options.registerOption(optionName, OptionType.FILE_TYPE, defaultValue, help, "Description");

		File optionValue = options.getFile(optionName, null);
		assertNull(optionValue);

		File file = new File(".");
		options.putObject(optionName, file);
		optionValue = options.getFile(optionName, null);
		assertEquals(file, optionValue);

		// clear the value
		options.putObject(optionName, null);
		optionValue = options.getFile(optionName, null);
		assertNull(optionValue);
	}

	@Test
	public void testSetNonNullableOptionToNull() {
		//
		// Some options cannot be null.  Verify that is the ca.
		//

		Options options = loadSearchOptions();

		HelpLocation help = null;
		int defaultValue = 1;
		String optionName = "Foo Int";
		options.registerOption(optionName, defaultValue, help, "Description");

		int optionValue = options.getInt(optionName, -1);
		assertEquals(defaultValue, optionValue);

		try {
			options.putObject(optionName, null);
			fail("Did not get expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		int newValue = 2;
		options.putObject(optionName, newValue);
		optionValue = options.getInt(optionName, -1);
		assertEquals(newValue, optionValue);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertAllDefaultOptions(ToolOptions options) {
		assertFalse(
			"Options unexpectedly have non-default values: " + printNonDefaultValues(options),
			hasNonDefaultValues(options));
	}

	private boolean hasNonDefaultValues(Options options) {
		List<String> optionNames = options.getOptionNames();
		for (String string : optionNames) {
			if (!options.isDefaultValue(string)) {
				return true;
			}
		}
		return false;
	}

	private void assertOnlyNonDefaultOption(Options options, String optionName) {
		List<String> names = options.getOptionNames();
		for (String name : names) {
			if (!optionName.equals(name)) {
				assertTrue("Found unexpected non-default value - name: " + name + ", value: " +
					options.getObject(name, null), options.isDefaultValue(name));
			}
		}

		//
		// Note: if we ask if the value of the option is default, it will return true when 
		//       the options have been reloaded, but not accessed by anyone.  However, on the 
		//       next load, before the untouched options have been removed, the option will exist
		//       and we can check that via hasProperty().
		//
		assertTrue("Expected non-default value for option: " + optionName,
			options.contains(optionName));
	}

	private String printNonDefaultValues(Options options) {
		List<String> names = options.getOptionNames();
		for (String name : names) {
			if (!options.isDefaultValue(name)) {
				Msg.debug(this,
					"non-default - name: " + name + ", value: " + options.getObject(name, null));
			}
		}
		return "";
	}

	private ToolOptions loadSearchOptions() {
		return tool.getOptions("Search");
	}

	private Options loadKeyBindingOptions() {
		return tool.getOptions("Key Bindings");
	}

	private Pair<String, String> changeStringTestOption(Options options) {
		options.registerOption(NEW_TEST_OPTION_NAME, "HEY", null, "description");
		options.setString(NEW_TEST_OPTION_NAME, TEST_OPTION_STRING_VALUE);
		return new Pair<>(NEW_TEST_OPTION_NAME, TEST_OPTION_STRING_VALUE);
	}

	private String clearKeyBinding(Options options) {
		String keyBindingName = "Go To Next Function (CodeBrowserPlugin)";
		KeyStroke ks = options.getKeyStroke(keyBindingName, null);
		assertNotNull(ks);
		options.setKeyStroke(keyBindingName, null);
		return keyBindingName;
	}

	private void verifyStringOptionStillChanged_WithoutUsingOptionsAPI(Options options,
			String optionName) {
		assertTrue("Options does not have an entry for test option", options.contains(optionName));
	}

	private void verifyStringOptionsStillChanged_UsingTheOptionsAPI(Options options,
			Pair<String, String> changedOption) {

		String storedValue = options.getString(NEW_TEST_OPTION_NAME, "Default Value!!!");
		assertEquals("Changed test option was not still set in the options", changedOption.second,
			storedValue);
	}

	private ToolOptions saveAndLoadOptions() {
		tool = saveTool(env.getProject(), tool); // saving the tool saves the options
		return loadSearchOptions();
	}

	private void verifyUnusedOptionNoLongerHasEntry(Options options, String optionName) {
		if (options.contains(optionName)) {
			Assert.fail("Options does not have an entry for test option - value: " +
				options.getObject(optionName, null));
		}
	}

	private void verifyKeyBindingIsStillCleared(Options options, String optionName) {
		KeyStroke ksValue = options.getKeyStroke(optionName, null);
		assertNull(ksValue);
	}

	private List<String> getDiffs(Map<String, Object> initialValues,
			Map<String, Object> latestValues) {
		List<String> diffs = new ArrayList<>();
		Set<String> keySet = initialValues.keySet();
		for (String key : keySet) {
			Object value = initialValues.get(key);
			Object newValue = latestValues.get(key);
			if (!value.equals(newValue)) {
				diffs.add(key + " - old:" + value + " - new:" + newValue);
			}
		}
		return diffs;
	}

}
