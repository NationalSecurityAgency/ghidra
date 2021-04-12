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
package ghidra.app.script;

import static org.junit.Assert.*;

import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.test.AbstractGTest;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.framework.main.DataTreeDialog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class GhidraScriptAskMethodsTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TEMP_SUB_DIR = "tempSubDir";

	/** A large timeout period that is usually not reached */
	private static final int TIMEOUT_MILLIS = 10000;

	private TestEnv env;
	private Program program;
	private GhidraState state;
	private GhidraScript script;

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x1000);
		builder.createMemory("test2", "0x1006000", 0x4000);
		program = builder.getProgram();

		env = new TestEnv();
		env.showTool(program);
		env.getTool().addPlugin(CodeBrowserPlugin.class.getName());
		env.getTool().addPlugin(GhidraScriptMgrPlugin.class.getName());

		ProgramLocation loc = new ProgramLocation(program, program.getMinAddress());

		state = new GhidraState(env.getTool(), env.getProject(), program, loc, null, null);
	}

	@After
	public void tearDown() throws Exception {

		clearScriptCachedValues();

		env.dispose();
	}

	private void clearScriptCachedValues() {
		if (script != null) {
			Map<?, ?> map = (Map<?, ?>) TestUtils.getInstanceField("askMap", script);
			map.clear();
		}
	}

	@Test
	public void testAskBytes_NoPreviousValue() throws Exception {
		createScript();
		askBytes("CC BB AA");

		// if we get here, then no exception happened--good!
	}

	/**
	 * Test that askBytes method auto-populates dialog with value in .properties file.
	 *
	 * Also test that subsequent calls to the dialog show the last-used value.
	 *
	 * @throws Exception
	 */
	@Test
	public void testAskBytes() throws Exception {
		createScript();

		// Compare default value to expected properties value
		String propertiesByteString = "AABBCCDD";
		byte[] myBytes = askBytes();
		assertByteArrayEquals(getBytesAsHex(propertiesByteString, 8), myBytes);

		// Set bytes to a different value. (Call the chooser and set the bytes, expecting that
		// the next call to askBytes will reuse this value.)
		String newByteString = "BB EE EE";
		askBytes(newByteString);

		myBytes = askBytes();
		byte[] expectedBytes = getBytesAsHex(newByteString.replaceAll("\\s", ""), 6);
		assertByteArrayEquals(expectedBytes, myBytes);
	}

	/*
	 * Calling askProgram() would stacktrace if the user 1) didn't select a program in the 
	 * tree and then 2) pressed the OK button.
	 */
	@Test
	public void testAskProgram_SCR8486() throws Exception {
		createScript();

		Program[] container = new Program[1];
		runSwing(() -> {
			try {
				container[0] = script.askProgram("Test - Pick Program");
			}
			catch (Exception ioe) {
				failWithException("Caught unexepected during askProgram()", ioe);
			}
		}, false);

		DataTreeDialog dtd = waitForDialogComponent(DataTreeDialog.class);
		JButton okButton = (JButton) getInstanceField("okButton", dtd);

		runSwing(() -> okButton.doClick());

		// this test will fail if we encountered an exception
		assertNull(container[0]);

		runSwing(() -> dtd.close());
	}

	/* 
	 * For scripts with properties files in a different location (could be the case with subscripts),
	 * tests that the .properties file is found in the default location and that the default value 
	 * for the input field is provided by the .properties file in the alternate location. 
	 * 
	 * @throws Exception
	 */
	@Test
	public void testAlternateLocationPropertiesFile() throws Exception {

		// Create a temporary .properties file and set the potentialPropertiesFileLocs to look 
		// in that location
		String tempDirPath = AbstractGTest.getTestDirectoryPath();
		File tempDir = new File(tempDirPath);
		File tempPropertiesFile = new File(tempDir, "GhidraScriptTest.properties");
		tempPropertiesFile.delete();

		final String[] myString = new String[1];

		String propertiesValue = "This is my alternate .properties location String.";
		final String defaultValue = "Is this the string you expected?";

		// Create .properties file that contains values for askString
		assertTrue("File '" + tempPropertiesFile.getAbsolutePath() + "' should have been created!",
			tempPropertiesFile.createNewFile());

		// Write the path to the file to the .properties file
		FileWriter output = new FileWriter(tempPropertiesFile);
		BufferedWriter writer = new BufferedWriter(output);
		writer.write("Test Alternate Location Please enter a string: = " + propertiesValue);
		writer.close();

		createScript();

		// Set .properties file location
		script.setPropertiesFileLocation(tempDirPath, "GhidraScriptTest");
		script.loadPropertiesFile();

		executeOnSwingWithoutBlocking(() -> {
			try {
				myString[0] = script.askString("Test Alternate Location", "Please enter a string:",
					defaultValue);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		AskDialog<?> askDialog = waitForDialogComponent(AskDialog.class);
		assertNotNull(askDialog);
		pressButtonByText(askDialog, "OK");
		waitForSwing();

		// Compare default value to expected properties value
		assertEquals(propertiesValue, myString[0]);

	}

	@Test
	public void testAskFile() throws Exception {

		// Create a temporary files, then create a temporary .properties file that contains
		// the path to one of the temporary file.
		String tempDirPath = AbstractGTest.getTestDirectoryPath();
		File tempDir = new File(tempDirPath);
		File tempFile = new File(tempDir, "tempFile.exe");
		File anotherTempFile = new File(tempDir, "MyTempFile.txt");
		File tempPropertiesFile = new File(tempDir, "tempPropertiesFile.properties");

		tempFile.delete();
		anotherTempFile.delete();
		tempPropertiesFile.delete();

		// First, create temporary files
		assertTrue("File '" + tempFile.getAbsolutePath() + "' should have been created!",
			tempFile.createNewFile());

		assertTrue("File '" + anotherTempFile.getAbsolutePath() + "' should have been created!",
			anotherTempFile.createNewFile());

		// Next, create .properties file that contains the path to the first temporary file
		assertTrue("File '" + tempPropertiesFile.getAbsolutePath() + "' should have been created!",
			tempPropertiesFile.createNewFile());

		// Write the path to the file to the .properties file
		FileWriter output = new FileWriter(tempPropertiesFile);
		BufferedWriter writer = new BufferedWriter(output);
		writer.write("Choose a file: Done! = " + tempFile.getAbsolutePath());
		writer.close();

		createScript();
		final File[] myFile = new File[1];

		// Load .properties value(s)
		script.setPropertiesFile(tempPropertiesFile);

		executeOnSwingWithoutBlocking(() -> {
			try {
				myFile[0] = script.askFile("Choose a file:", "Done!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		waitForUpdateOnDirectory(fileChooser);

		assertNotNull(fileChooser);
		pressButtonByText(fileChooser, "Done!");

		waitForSwing();

		// Compare default value to expected properties value
		assertEquals(tempFile, myFile[0]);

		// Choose another file and press ok
		executeOnSwingWithoutBlocking(() -> {
			try {
				myFile[0] = script.askFile("Choose a file:", "Done!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		fileChooser.setSelectedFile(anotherTempFile);
		waitForUpdateOnDirectory(fileChooser);

		pressButtonByText(fileChooser, "Done!");
		waitForSwing();

		// Verify the chosen file is auto-populated when the dialog comes up again
		executeOnSwingWithoutBlocking(() -> {
			try {
				myFile[0] = script.askFile("Choose a file:", "Done!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		fileChooser.setSelectedFile(anotherTempFile);
		waitForUpdateOnDirectory(fileChooser);

		pressButtonByText(fileChooser, "Done!");
		waitForSwing();

		assertEquals(anotherTempFile, myFile[0]);
	}

	/**
	 * Test that askDirectory method auto-populates dialog with value in .properties file.
	 *
	 * Also test that subsequent calls to the dialog show the last-used value.
	 *
	 * @throws Exception
	 */
	@Test
	public void testAskDirectory() throws Exception {

		// Create temporary directories, then create a temporary .properties file that contains
		// the path to one of the temporary directory.
		String tempDirPath = AbstractGTest.getTestDirectoryPath();
		File tempDir = new File(tempDirPath);
		File tempSubDir = new File(tempDir, TEMP_SUB_DIR);
		File anotherTempSubDir = new File(tempDir, "anotherTempDir");
		File tempPropertiesFile = new File(tempDir, "tempPropertiesFile.properties");
		tempPropertiesFile.deleteOnExit();

		FileUtilities.deleteDir(tempSubDir);
		FileUtilities.deleteDir(anotherTempSubDir);
		tempPropertiesFile.delete();

		// First, create temporary dirs
		assertTrue("Directory '" + tempSubDir.getAbsolutePath() + "' should have been created!",
			tempSubDir.mkdir());

		assertTrue(
			"Directory '" + anotherTempSubDir.getAbsolutePath() + "' should have been created!",
			anotherTempSubDir.mkdir());

		// Next, create .properties file that contains the path to one of the dirs
		assertTrue("File '" + tempPropertiesFile.getAbsolutePath() + "' should have been created!",
			tempPropertiesFile.createNewFile());

		// Write the path to the file to the .properties file
		FileWriter output = new FileWriter(tempPropertiesFile);
		BufferedWriter writer = new BufferedWriter(output);
		writer.write("Choose your directory: Choose! = " + tempSubDir.getAbsolutePath());
		writer.close();

		createScript();
		final File[] myDir = new File[1];

		// Load .properties value(s)
		script.setPropertiesFile(tempPropertiesFile);

		executeOnSwingWithoutBlocking(() -> {
			try {
				myDir[0] = script.askDirectory("Choose your directory:", "Choose!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		waitForUpdateOnDirectory(fileChooser);

		assertNotNull(fileChooser);
		pressButtonByText(fileChooser, "Choose!");

		waitForSwing();

		// Compare default value to expected properties value
		assertEquals(tempSubDir, myDir[0]);

		// Choose another directory
		executeOnSwingWithoutBlocking(() -> {
			try {
				myDir[0] = script.askDirectory("Choose your directory:", "Choose!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		fileChooser = waitForDialogComponent(GhidraFileChooser.class);

		fileChooser.setSelectedFile(anotherTempSubDir);
		waitForUpdateOnDirectory(fileChooser);

		pressButtonByText(fileChooser, "Choose!");
		waitForSwing();

		// Verify the directory we chose is auto-populated when the dialog comes up again
		executeOnSwingWithoutBlocking(() -> {
			try {
				myDir[0] = script.askDirectory("Choose your directory:", "Choose!");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		});

		fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		waitForUpdateOnDirectory(fileChooser);

		pressButtonByText(fileChooser, "Choose!");
		waitForSwing();

		assertEquals(anotherTempSubDir, myDir[0]);

		FileUtilities.deleteDir(tempSubDir);
		FileUtilities.deleteDir(anotherTempSubDir);
	}

	/**
	 * Test that askLanguage method auto-populates dialog with value in .properties file.
	 *
	 * Also test that subsequent calls to the dialog show the last-used value.
	 *
	 * @throws Exception
	 */
	@Test
	public void testAskLanguage() throws Exception {
		createScript();

		LanguageCompilerSpecPair[] myLang = new LanguageCompilerSpecPair[1];

		runSwing(() -> {
			try {
				myLang[0] = script.askLanguage("Ask Test", "Give me a language:");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		SelectLanguageDialog langDialog = waitForDialogComponent(SelectLanguageDialog.class);
		assertNotNull(langDialog);
		pressButtonByText(langDialog, "Give me a language:");
		waitForSwing();

		// Compare default value to expected properties value
		assertEquals(new LanguageCompilerSpecPair("6502:LE:16:default", "default"), myLang[0]);

		// Set language do something else
		runSwing(() -> {
			try {
				myLang[0] = script.askLanguage("Ask Test", "Give me a language:");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		langDialog = waitForDialogComponent(SelectLanguageDialog.class);

		LanguageCompilerSpecPair chosenLang =
			new LanguageCompilerSpecPair("68000:BE:32:Coldfire", "default");
		langDialog.setSelectedLanguage(chosenLang);
		waitForSwing();

		pressButtonByText(langDialog, "Give me a language:");
		waitForSwing();

		// Verify that the last-chosen language is auto-populated in the dialog box
		runSwing(() -> {
			try {
				myLang[0] = script.askLanguage("Ask Test", "Give me a language:");
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		langDialog = waitForDialogComponent(SelectLanguageDialog.class);

		pressButtonByText(langDialog, "Give me a language:");
		waitForSwing();

		assertEquals(chosenLang, myLang[0]);

	}

	/*
	 * Test that askInt method auto-populates dialog with value in .properties file.
	 *	 
	 * Also test that subsequent calls to the dialog show the last-used value.
	 */
	@Test
	public void testAskInt() throws Exception {
		createScript();

		// Compare default value to expected properties value
		int chosenInt = ask_TextInput(() -> {
			return script.askInt("Ask Test", "Enter an integer:");
		});
		assertEquals(10101, chosenInt);

		// Now set int to some other value
		Integer newInt = 123456;
		chosenInt = ask_TextInput(Integer.toString(newInt), () -> {
			return script.askInt("Ask Test", "Enter an integer:");
		});

		// See if the last-set value is auto-populated
		chosenInt = ask_TextInput(() -> {
			return script.askInt("Ask Test", "Enter an integer:");
		});
		assertEquals(newInt.intValue(), chosenInt);
	}

	/*
	 * Test that askLong method auto-populates dialog with value in .properties file.
	 *
	 * Also test that subsequent calls to the dialog show the last-used value.
	 */
	@Test
	public void testAskLong() throws Exception {
		createScript();

		long chosenLong = ask_TextInput(() -> {
			return script.askLong("Ask Test", "Enter a long:");
		});

		// Compare default value to expected properties value
		assertEquals((long) Math.pow(2, 18), chosenLong);

		// Now set the long value to a different value
		Long newLong = (long) Math.pow(4, 28);
		chosenLong = ask_TextInput(Long.toString(newLong), () -> {
			return script.askLong("Ask Test", "Enter a long:");
		});

		// See if the last-set value is auto-populated
		chosenLong = ask_TextInput(() -> {
			return script.askLong("Ask Test", "Enter a long:");
		});

		assertEquals(newLong.longValue(), chosenLong);
	}

	/*
	 * Test that askAddress method auto-populates dialog with value in .properties file.
	 *
	 * Also test that subsequent calls to the dialog show the last-used value.
	 */
	@Test
	public void testAskAddress() throws Exception {
		createScript();

		Address chosenAddress = ask_TextInput(() -> {
			return script.askAddress("Ask Test", "Enter an address:");
		});

		// Compare default value to expected properties value
		assertEquals(addr("100f1d0"), chosenAddress);

		// Set the address to a different value
		String newAddressString = "100888";
		chosenAddress = ask_TextInput(newAddressString, () -> {
			return script.askAddress("Ask Test", "Enter an address:");
		});

		// See if the last-set value is auto-populated
		chosenAddress = ask_TextInput(() -> {
			return script.askAddress("Ask Test", "Enter an address:");
		});

		assertEquals(addr(newAddressString), chosenAddress);
	}

	@Test
	public void testAskDouble() throws Exception {
		createScript();

		// Compare default value to expected properties value
		double chosenDouble = ask_TextInput(() -> {
			return script.askDouble("Ask Test", "Enter a double:");
		});
		assertEquals(1.0035d, chosenDouble, .00001);

		// Set another double value
		Double newDouble = 4.2526;
		ask_TextInput(Double.toString(newDouble), () -> {
			return script.askDouble("Ask Test", "Enter a double:");
		});

		// See if the last-set value is auto-populated
		chosenDouble = ask_TextInput(() -> {
			return script.askDouble("Ask Test", "Enter a double:");
		});
		assertEquals(newDouble.doubleValue(), chosenDouble, .0001);
	}

	@Test
	public void testAskString() throws Exception {
		createScript();

		// Compare default value to expected properties value
		String chosenString = ask_TextInput(() -> {
			return script.askString("Ask Test", "Enter a string:");
		});
		assertEquals("feedme", chosenString);

		// Set String to a different value
		String newString = "This is an entirely new string.";
		ask_TextInput(newString, () -> {
			return script.askString("Ask Test", "Enter a string:");
		});

		// See if the last-set value is auto-populated
		chosenString = ask_TextInput(() -> {
			return script.askString("Ask Test", "Enter a string:");
		});
		assertEquals(newString, chosenString);
	}

	/*
	 * Test that askString method auto-populates dialog with user-supplied default value (in the
	 * absence of a .properties file).
	 */
	@Test
	public void testAskStringDefaultValue() throws Exception {

		createScript();

		final String defaultValue = "a default value";
		String myString = ask_TextInput(() -> {
			return script.askString("Default Test", "Enter a string here:", defaultValue);
		});
		assertEquals(defaultValue, myString);
	}

	@Test
	public void testAskChoice() throws Exception {
		createScript();

		// Compare default value to expected properties value
		List<String> choices = Arrays.asList("eenie", "meanie", "miney", "mo");
		String chosen = ask_ComboInput(() -> {
			return script.askChoice("Ask Test", "Choose one:", choices, "mo");
		});
		assertEquals("meanie", chosen);

		// Set choice to a different value
		String choice_eenie = choices.get(0);
		chosen = ask_ComboInput(choice_eenie, () -> {
			return script.askChoice("Ask Test", "Choose one:", choices, "mo");
		});
		assertEquals(choice_eenie, chosen);

		// See if the last-set value is auto-populated
		String choice_miney = choices.get(2);
		chosen = ask_ComboInput(() -> {
			// Note: we are passing a default of 'miney', but expect the last choice of 'eenie'
			return script.askChoice("Ask Test", "Choose one:", choices, choice_miney);
		});
		assertEquals(choice_eenie, chosen);
	}

	/**
	 * Test that askChoice method auto-populates dialog with user-supplied default value (in the
	 * absence of a .properties file).
	 *
	 * @throws Exception
	 */
	@Test
	public void testAskChoiceDefaultValue() throws Exception {
		createScript();

		List<String> choices = Arrays.asList("one fish", "two fish", "red fish", "blue fish");
		int choiceIndex = 2;
		String chosen = ask_ComboInput(() -> {
			return script.askChoice("Ask Default Choice Test",
				"Which choice would you like to pick?", choices, choices.get(choiceIndex));
		});
		assertEquals(choices.get(choiceIndex), chosen);
	}

	// TODO test for askChoices()	

	/* 
	 * No test for either of the two versions of 'askChoices()" because it does not use either the 
	 * the last-selected value or a .properties file value to pre-populate the user choice in the 
	 * GUI. 
	 */

	/* 
	 * No test for 'askYesNo()" because it does not use either the the last-selected value or
	 * a .properties file value to pre-populate the user choice in the GUI. 
	 */

	/* 
	 * No test for 'askProjectFolder()" because it does not use either the the last-selected value 
	 * or a .properties file value to pre-populate the user choice in the GUI. 
	 */

	/* 
	 * No test for 'askProgram()" because it does not use either the the last-selected value or
	 * a .properties file value to pre-populate the user choice in the GUI. 
	 */

	/* 
	 * No test for 'askDomainFile()" because it does not use either the the last-selected value or
	 * a .properties file value to pre-populate the user choice in the GUI. 
	 */

//==================================================================================================
// Private Methods
//==================================================================================================	

	private <T> T ask_ComboInput(Callable<T> c) {
		return ask_TextInput(null, c);
	}

	private <T> T ask_ComboInput(String optionalValue, Callable<T> c) {

		AtomicReference<T> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				T t = c.call();
				ref.set(t);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		DialogComponentProvider askDialog = waitForDialogComponent(DialogComponentProvider.class);
		assertNotNull(askDialog);

		if (optionalValue != null) {
			@SuppressWarnings("unchecked")
			JComboBox<String> comboField =
				(JComboBox<String>) findComponentByName(askDialog, "JComboBox");
			setComboBoxSelection(comboField, optionalValue);
			waitForSwing();
		}

		pressButtonByText(askDialog, "OK");
		waitForSwing();

		return ref.get();
	}

	private <T> T ask_TextInput(Callable<T> c) {
		return ask_TextInput(null, c);
	}

	private <T> T ask_TextInput(String optionalValue, Callable<T> c) {

		AtomicReference<T> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				T t = c.call();
				ref.set(t);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		DialogComponentProvider askDialog = waitForDialogComponent(DialogComponentProvider.class);
		assertNotNull(askDialog);

		if (optionalValue != null) {
			String name = "JTextField";
			JTextField textField = (JTextField) findComponentByName(askDialog, name);
			setText(textField, optionalValue);
			waitForSwing();
		}

		pressButtonByText(askDialog, "OK");
		waitForSwing();

		return ref.get();
	}

	private byte[] askBytes() {
		return askBytes(null);
	}

	private byte[] askBytes(String optionalValue) {

		AtomicReference<byte[]> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				byte[] b = script.askBytes("Ask Test", "Enter bytes:");
				ref.set(b);
			}
			catch (Exception e) {
				failWithException("Exception was caught in this test: " + e.getMessage(), e);
			}
		}, false);

		AskDialog<?> askDialog = waitForDialogComponent(AskDialog.class);
		assertNotNull(askDialog);

		if (optionalValue != null) {
			String name = "JTextField";
			JTextField textField = (JTextField) findComponentByName(askDialog, name);
			setText(textField, optionalValue);
			waitForSwing();
		}

		pressButtonByText(askDialog, "OK");
		waitForSwing();

		return ref.get();
	}

	// waits for the given change ID to change...also attempts to wait out a barrage of changes
	private void waitForUpdateOnDirectory(GhidraFileChooser chooser) throws Exception {
		// make sure swing has handled any pending changes
		waitForSwing();

		// artificially high wait period that won't be reached most of the time
		int timeoutMillis = TIMEOUT_MILLIS;
		int totalTime = 0;

		while (hasPendingUpdate(chooser) && (totalTime < timeoutMillis)) {
			Thread.sleep(50);
			totalTime += 50;
		}

		if (totalTime >= timeoutMillis) {
			Assert.fail("Timed-out waiting for directory to load");
		}

		// make sure swing has handled any pending changes
		waitForSwing();
	}

	private boolean hasPendingUpdate(GhidraFileChooser chooser) {
		return (Boolean) invokeInstanceMethod("pendingUpdate", chooser);
	}

	private void assertByteArrayEquals(byte[] array1, byte[] array2) {

		if (array1.length != array2.length) {
			Assert.fail(
				"Byte array lengths should be equal: " + array1.length + " and " + array2.length +
					"; values: " + Arrays.toString(array1) + " and " + Arrays.toString(array2));
			return;
		}

		for (int i = 0; i < array1.length; i++) {
			assertEquals(array1[i], array2[i]);
		}
	}

	private byte[] getBytesAsHex(String str, int len) throws NumberFormatException {

		byte[] bytes = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			String sub = str.substring(i, i + 2);// get byte substring
			// turn substring into hex Integer
			Integer iByte = Integer.valueOf(sub, 16);
			bytes[i / 2] = iByte.byteValue();// turn hex Integer into byte
		}

		return bytes;
	}

	private Address addr(String text) {
		AddressFactory addrFactory = program.getAddressFactory();
		return addrFactory.getAddress(text);
	}

	private void createScript() throws Exception {
		script = new GhidraScript() {
			@Override
			public void run() throws Exception {
				// test stub
			}
		};
		script.set(state, TaskMonitor.DUMMY, null);

		URL url = GhidraScriptTest.class.getResource("GhidraScriptAsk.properties");
		assertNotNull("Test cannot run without properties file!", url);
		File propertiesFile = new File(url.toURI());
		script.setPropertiesFile(propertiesFile);
	}

}
