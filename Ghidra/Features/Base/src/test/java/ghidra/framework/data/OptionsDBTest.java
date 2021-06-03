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
package ghidra.framework.data;

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyChangeListener;
import java.beans.PropertyEditorSupport;
import java.io.File;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.KeyStroke;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.options.*;
import ghidra.framework.options.OptionsTest.FRUIT;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.util.HelpLocation;
import ghidra.util.exception.InvalidInputException;

public class OptionsDBTest extends AbstractGenericTest {

	private OptionsDB options;
	private ProgramBuilder builder;
	private int txID;

	public enum fruit {
		Apple, Pear, Orange
	}

	public OptionsDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder();
		ProgramDB program = builder.getProgram();
		txID = program.startTransaction("Test");
		options = new OptionsDB(program);
	}

	private void saveAndRestoreOptions() {
		options = new OptionsDB(builder.getProgram());
	}

	@After
	public void tearDown() throws Exception {
		builder.getProgram().endTransaction(txID, false);
		builder.dispose();
	}

	@Test
	public void testInt() {
		options.setBoolean("foo", true);
		assertEquals(true, options.getBoolean("foo", false));
	}

	@Test
	public void testEnum() {
		options.setEnum("foo", fruit.Pear);
		assertEquals(fruit.Pear, options.getEnum("foo", fruit.Apple));
	}

	@Test
	public void testCustomOption() {
		MyCustomOption co = new MyCustomOption(10);
		options.setCustomOption("foo", co);
		options.clearCache();
		CustomOption retrieved = options.getCustomOption("foo", null);
		assertTrue(co != retrieved);
		assertEquals(co, retrieved);
	}

	@Test
	public void testRegisterTwiceDifferentValuesNoTransaction() {
		// we want to test registering without a transaction and setup
		// start one for convenience.
		builder.getProgram().endTransaction(txID, false);

		options.registerOption("bob", OptionType.FILE_TYPE, null, null, "Help description");
		options.registerOption("bob", OptionType.FILE_TYPE, new File(""), null, "Help description");

		// open a transaction back again so tear down will be happy
		txID = builder.getProgram().startTransaction("Test");
	}

	//-------------------------------
	@Test
	public void testGettingDefaultWhenNoOptionsExist() {
		assertEquals(5, options.getInt("Foo", 5));
	}

	@Test
	public void testGetName() {
		assertEquals("", options.getName());
	}

	@Test
	public void testGettingValueWhenAlreadySet() {
		options.setInt("Foo", 32);
		assertEquals(32, options.getInt("Foo", 5));
	}

	@Test
	public void testDefaultsNotSaved() {
		options.registerOption("Foo", 5, null, "description");
		assertTrue(options.contains("Foo"));
		assertEquals(5, options.getInt("Foo", 0));
		saveAndRestoreOptions();
		assertFalse(options.contains("Foo"));
	}

	@Test
	public void testMixingTypesForSameName() {
		options.setInt("Foo", 5);
		try {
			options.getString("Foo", "Default");
			Assert.fail("Expected Illegal State Exception");
		}
		catch (IllegalStateException e) {
			// expected
		}
	}

	@Test
	public void testSaveIntOption() {
		options.setInt("Foo", 32);
		saveAndRestoreOptions();
		assertEquals(32, options.getInt("Foo", 5));
	}

	@Test
	public void testSaveLongOption() {
		options.setLong("Foo", 5);
		saveAndRestoreOptions();
		assertEquals(5, options.getLong("Foo", 5));
	}

	@Test
	public void testSaveFloatOption() {
		options.setFloat("Foo", (float) 5.3);
		saveAndRestoreOptions();
		assertEquals((float) 5.3, options.getFloat("Foo", 0), 0);
	}

	@Test
	public void testSaveDoubleOption() {
		options.setDouble("Foo", 5.3);
		saveAndRestoreOptions();
		assertEquals(5.3, options.getDouble("Foo", 0), 0);
	}

	@Test
	public void testSaveBooleanOption() {
		options.setBoolean("Bool", true);
		saveAndRestoreOptions();
		assertEquals(true, options.getBoolean("Bool", false));
	}

	@Test
	public void testSaveStringOption() {
		options.setString("Foo", "Hey");
		saveAndRestoreOptions();
		assertEquals("Hey", options.getString("Foo", "Default"));
	}

	@Test
	public void testSaveByteArray() {
		byte[] bytes = new byte[] { (byte) 1, (byte) 2, (byte) 3 };
		options.setByteArray("BYTES", bytes);
		saveAndRestoreOptions();
		assertTrue(Arrays.equals(bytes, options.getByteArray("BYTES", null)));
	}

	@Test
	public void testSaveColorOption() {
		options.setColor("Foo", Color.RED);
		saveAndRestoreOptions();
		assertEquals(Color.RED, options.getColor("Foo", Color.BLUE));
	}

	@Test
	public void testSaveFileOption() {
		File file = new File("/Users/foo").getAbsoluteFile();
		options.setFile("Foo", file);
		saveAndRestoreOptions();
		assertEquals(file, options.getFile("Foo", new File("/")));
	}

	@Test
	public void testSaveDateOption() {
		Date date = new Date();
		options.setDate("Foo", date);
		saveAndRestoreOptions();
		assertEquals(date, options.getDate("Foo", new Date()));
	}

	@Test
	public void testSaveKeyStrokeOption() {
		options.setKeyStroke("Foo", KeyStroke.getKeyStroke('a', 0));
		saveAndRestoreOptions();
		assertEquals(KeyStroke.getKeyStroke('a', 0),
			options.getKeyStroke("Foo", KeyStroke.getKeyStroke('b', 0)));
	}

	@Test
	public void testSaveFontOption() {
		Font font = new Font("Monospaced", Font.BOLD, 12);
		options.setFont("Foo", font);
		saveAndRestoreOptions();
		assertEquals(font, options.getFont("Foo", null));
	}

	@Test
	public void testSaveCustomOption() {
		MyCustomOption option = new MyCustomOption(7);
		options.setCustomOption("Foo", option);
		assertEquals(option, options.getCustomOption("Foo", new MyCustomOption(3)));
		saveAndRestoreOptions();
		assertEquals(option, options.getCustomOption("Foo", new MyCustomOption(3)));
	}

	@Test
	public void testSaveEnumOption() {
		options.setEnum("SNACK", FRUIT.Orange);
		assertEquals(FRUIT.Orange, options.getEnum("SNACK", (FRUIT) null));

		saveAndRestoreOptions();
		assertEquals(FRUIT.Orange, options.getEnum("SNACK", (FRUIT) null));
	}

	@Test
	public void testPuttingNonSaveableObject() {
		try {
			options.putObject("FOO", new Object());
			Assert.fail("Should not have been able to put a non-saveable object");
		}
		catch (Exception e) {
			// expected
		}
	}

	@Test
	public void testRemove() {
		options.setColor("COLOR", Color.RED);
		assertTrue(options.contains("COLOR"));
		options.removeOption("COLOR");
		assertTrue(!options.contains("COLOR"));

	}

	@Test
	public void testGetOptionNames() {
		options.setColor("COLOR", Color.red);
		options.setInt("INT", 3);
		List<String> optionNames = options.getOptionNames();
		assertTrue(optionNames.contains("COLOR"));
		assertTrue(optionNames.contains("INT"));
	}

	@Test
	public void testGetDefaultValue() {
		options.registerOption("Foo", Color.RED, null, "description");
		options.setColor("Foo", Color.BLUE);
		assertEquals(Color.BLUE, options.getColor("Foo", null));
		assertEquals(Color.RED, options.getDefaultValue("Foo"));
	}

	@Test
	public void testRegisterPropertyEditor() {
		MyPropertyEditor editor = new MyPropertyEditor();
		options.registerOption("color", OptionType.COLOR_TYPE, Color.RED, null, "description",
			editor);
		assertEquals(editor, options.getRegisteredPropertyEditor("color"));

	}

	@Test
	public void testGetHelpLocation() {
		HelpLocation helpLocation = new HelpLocation("topic", "anchor");
		options.registerOption("Foo", 3, helpLocation, "description");
		assertEquals(helpLocation, options.getHelpLocation("Foo"));
	}

	@Test
	public void testRestoreOptionValue() {
		options.registerOption("Foo", Color.RED, null, "description");
		options.setColor("Foo", Color.BLUE);
		assertEquals(Color.BLUE, options.getColor("Foo", null));
		options.restoreDefaultValue("Foo");
		assertEquals(Color.RED, options.getColor("Foo", null));

	}

	@Test
	public void testOptionsHelp() {
		assertNull(options.getOptionsHelpLocation());
		HelpLocation helpLocation = new HelpLocation("topic", "anchor");
		options.setOptionsHelpLocation(helpLocation);
		assertEquals(helpLocation, options.getOptionsHelpLocation());

		Options subOptions = options.getOptions("SUB");
		assertNull(subOptions.getOptionsHelpLocation());
		subOptions.setOptionsHelpLocation(helpLocation);
		assertEquals(helpLocation, subOptions.getOptionsHelpLocation());
	}

	@Test
	public void testIllegalNames() {
		try {
			options.setInt("a..b", 3);
			Assert.fail("Didn't catch bad option name");
		}
		catch (Exception e) {
			//expected
		}

		try {
			options.setInt(".a", 3);
			Assert.fail("Didn't catch bad option name");
		}
		catch (Exception e) {
			//expected
		}

		try {
			options.setInt("a.", 3);
			Assert.fail("Didn't catch bad option name");
		}
		catch (Exception e) {
			//expected
		}
	}

	@Test
	public void testIsDefaultValue() {
		assertTrue(options.isDefaultValue("Foo"));
		options.getInt("Foo", 2);
		assertTrue(options.isDefaultValue("Foo"));
		options.setInt("Foo", 3);
		assertTrue(!options.isDefaultValue("Foo"));
	}

	@Test
	public void testIsRegistered() {
		assertTrue(!options.isRegistered("Foo"));
		options.setInt("Foo", 3);
		assertTrue(options.isRegistered("Foo"));

		assertTrue(!options.isRegistered("Bar"));
		options.getInt("Bar", 10);
		assertTrue(!options.isRegistered("Bar"));

		assertTrue(!options.isRegistered("aaa"));
		options.registerOption("aaa", 3, null, "description");
		assertTrue(options.isRegistered("aaa"));

	}

	@Test
	public void testRestoreDefaults() {
		options.registerOption("Foo", 10, null, "description");
		options.setInt("Foo", 2);
		options.registerOption("Bar", 100, null, "description");
		options.setInt("Bar", 1);
		options.restoreDefaultValues();
		assertEquals(10, options.getInt("Foo", 0));
		assertEquals(100, options.getInt("Bar", 0));
	}

	@Test
	public void testDescription() {
		assertEquals("Unregistered Option", options.getDescription("Foo"));
		options.registerOption("Foo", 5, null, "Hey");
		assertEquals("Hey", options.getDescription("Foo"));
		options.setInt("Foo", 3);
		assertEquals("Hey", options.getDescription("Foo"));

		options.registerOption("Foo", 7, null, "There");// first register wins!
		assertEquals("Hey", options.getDescription("Foo"));
	}

	@Test
	public void testCopyOptions() {
		options.setInt("INT", 3);
		options.setColor("COLOR", Color.RED);
		ToolOptions options2 = new ToolOptions("aaa");
		options2.copyOptions(options);
		assertEquals(3, options.getInt("INT", 3));
		assertEquals(Color.RED, options.getColor("COLOR", null));
	}

	@Test
	public void testSubOptions() {
		options.setInt("Z", 1);
		options.setInt("A.B", 2);
		options.setInt("A.D.E", 3);
		options.setInt("B.F", 4);

		List<Options> childOptions = options.getChildOptions();
		assertEquals(3, childOptions.size());
		assertEquals("A", childOptions.get(0).getName());
		assertEquals("B", childOptions.get(1).getName());
		assertEquals("Program Information", childOptions.get(2).getName());

		Options childOptions0 = childOptions.get(0);
		List<String> optionNames = childOptions0.getOptionNames();
		assertEquals(2, optionNames.size());
		assertEquals("B", optionNames.get(0));
		assertEquals("D.E", optionNames.get(1));

		List<Options> grandChildOptions = childOptions0.getChildOptions();
		assertEquals(1, grandChildOptions.size());
		assertEquals("E", grandChildOptions.get(0).getOptionNames().get(0));
		assertEquals(3, grandChildOptions.get(0).getInt("E", 0));
	}

	@Test
	public void testAlias() {
		options.setInt("AAA", 4);
		options.createAlias("BBB", options, "AAA");

		assertEquals(4, options.getInt("BBB", 0));
		assertTrue(options.isAlias("BBB"));
		assertFalse(options.isAlias("AAA"));
	}

	@Test
	public void testAliasAcrossSubOptions() {
		Options fooOptions = options.getOptions("Foo");
		Options barOptions = options.getOptions("Bar");
		fooOptions.setInt("XXX", 5);
		barOptions.createAlias("YYY", fooOptions, "XXX");
		assertEquals(5, barOptions.getInt("YYY", 0));

		barOptions.setInt("YYY", 10);
		assertEquals(10, fooOptions.getInt("XXX", 0));

	}

	@Test
	public void testGetLeafOptionNames() {
		options.setInt("aaa", 5);
		options.setInt("bbb", 6);
		options.setInt("ccc.ddd", 10);
		List<String> leafOptionNames = options.getLeafOptionNames();
		assertEquals(2, leafOptionNames.size());
		assertTrue(leafOptionNames.contains("aaa"));
		assertTrue(leafOptionNames.contains("bbb"));
	}

	@Test
	public void testGetLeafOptionNamesInSubOptions() {
		Options subOptions = options.getOptions("foo");
		subOptions.setInt("aaa", 5);
		subOptions.setInt("bbb", 6);
		subOptions.setInt("ccc.ddd", 10);
		List<String> leafOptionNames = subOptions.getLeafOptionNames();
		assertEquals(2, leafOptionNames.size());
		assertTrue(leafOptionNames.contains("aaa"));
		assertTrue(leafOptionNames.contains("bbb"));
	}

	@Test
	public void testGetID() {
		Options subOptions = options.getOptions("foo");
		subOptions.setInt("aaa", 5);
		assertEquals("foo.aaa", subOptions.getID("aaa"));
	}

	@Test
	public void testGetValueAsString() {
		options.setInt("foo", 5);
		assertEquals("5", options.getValueAsString("foo"));
		assertNull(options.getValueAsString("bar"));
	}

	@Test
	public void testGetDefaultValueAsString() {
		options.registerOption("foo", 7, null, "description");
		options.setInt("foo", 5);
		assertEquals("7", options.getDefaultValueAsString("foo"));
		assertNull(options.getDefaultValueAsString("bar"));
	}

	@Test
	public void testResgisteringOptionWithNullValue() {
		try {
			options.registerOption("Foo", null, null, "description");
			Assert.fail("Should not be able to register an options with a default value");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testRegisteringOptionWithUnsupportedType() {
		try {
			options.registerOption("Foo", new ArrayList<String>(), null, "description");
			Assert.fail(
				"Should not be able to register an options with an ArrayList as a default value");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testRegisteringOptionWithTypeNone() {
		try {
			options.registerOption("Foo", OptionType.NO_TYPE, null, null, "description");
			Assert.fail("Should not be able to register an options of type NONE");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testRegisteringOptionsEditor() {
		MyOptionsEditor myOptionsEditor = new MyOptionsEditor();
		options.registerOptionsEditor(myOptionsEditor);
		assertEquals(myOptionsEditor, options.getOptionsEditor());
		Options subOptions = options.getOptions("SUB");
		subOptions.registerOptionsEditor(myOptionsEditor);
		assertEquals(myOptionsEditor, subOptions.getOptionsEditor());

	}

	@Test
	public void testSettingValueToNull() {
		options.registerOption("Bar", Color.BLUE, null, "description");
		options.setColor("Bar", Color.red);
		options.setColor("Bar", null);
		assertEquals(null, options.getColor("Bar", null));
	}

	@Test
	public void testNullValueWillUsedPassedInDefault() {
		options.setColor("Bar", Color.red);
		options.setColor("Bar", null);
		assertEquals(Color.BLUE, options.getColor("Bar", Color.BLUE));
	}

	@Test
	public void testGetType() {
		options.setInt("fool", 5);
		assertEquals(OptionType.INT_TYPE, options.getType("fool"));
		assertEquals(OptionType.NO_TYPE, options.getType("bar"));// there is no bar
	}

	//--------------------------------
	// custom options must be public
	public static class MyCustomOption implements CustomOption {
		int value;

		public MyCustomOption() {
			// used by reflection
		}

		MyCustomOption(int value) {
			this.value = value;
		}

		@Override
		public void readState(SaveState saveState) {
			value = saveState.getInt("VALUE", 0);
		}

		@Override
		public void writeState(SaveState saveState) {
			saveState.putInt("VALUE", value);
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof MyCustomOption) {
				return ((MyCustomOption) obj).value == value;
			}
			return false;
		}

		@Override
		public int hashCode() {
			return 0;
		}
	}

	static class MyOptionsEditor implements OptionsEditor {

		@Override
		public void apply() throws InvalidInputException {
			// dummy
		}

		@Override
		public void dispose() {
			// dummy
		}

		@Override
		public void cancel() {
			// dummy
		}

		@Override
		public void reload() {
			// dummy
		}

		@Override
		public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
			// dummy
		}

		@Override
		public JComponent getEditorComponent(Options options,
				EditorStateFactory editorStateFactory) {
			return null;
		}

	}

	public static class MyPropertyEditor extends PropertyEditorSupport {

	}

}
