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
package ghidra.app.util.viewer.field;

import static org.junit.Assert.*;

import javax.swing.SwingUtilities;

import org.junit.*;

import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.util.SourceMapFieldLocation;
import ghidra.test.*;

public class SourceMapFieldFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private ProgramBuilder builder;
	private Program program;
	private Function entry;
	private Address entryPoint;
	private CodeBrowserPlugin cb;
	private Options fieldOptions;
	private SourceFileManager sourceManager;
	private static final String SOURCE1_NAME = "test1.c";
	private static final String SOURCE1_PATH = "/dir1/" + SOURCE1_NAME;
	private static final String SOURCE2_NAME = "test2.c";
	private static final String SOURCE2_PATH = "/dir2/dir2/" + SOURCE2_NAME;
	private SourceFile source1;
	private SourceFile source2;
	private static final int ROW = 0;
	private static final int COLUMN = 0;

	@Before
	public void setUp() throws Exception {
		init();
		entryPoint = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1006420);
		entry = program.getFunctionManager().getFunctionAt(entryPoint);
		env = new TestEnv();
		env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);
		SourceMapFieldFactory factory = new SourceMapFieldFactory();
		runSwing(() -> cb.getFormatManager().getCodeUnitFormat().addFactory(factory, ROW, COLUMN));
		fieldOptions = cb.getFormatManager().getFieldOptions();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testNoSourceInfo() throws Exception {
		assertNotNull(entry);
		setBooleanOption(SourceMapFieldFactory.SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, false);
		assertFalse(cb.goToField(entryPoint, SourceMapFieldFactory.FIELD_NAME, ROW, COLUMN));
		setBooleanOption(SourceMapFieldFactory.SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, true);
		ListingTextField textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
		assertEquals(SourceMapFieldFactory.NO_SOURCE_INFO, textField.getText());

	}

	@Test
	public void testShowFilename() throws Exception {
		int txID = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, entryPoint, 2);
		}
		finally {
			program.endTransaction(txID, true);
		}
		setBooleanOption(SourceMapFieldFactory.SHOW_FILENAME_ONLY_OPTION_NAME, false);
		ListingTextField textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_PATH + ":1 (2)", textField.getText());

		setBooleanOption(SourceMapFieldFactory.SHOW_FILENAME_ONLY_OPTION_NAME, true);
		textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_NAME + ":1 (2)", textField.getText());
	}

	@Test
	public void testShowIdentifier() throws Exception {
		int txID = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, entryPoint, 2);
		}
		finally {
			program.endTransaction(txID, true);
		}
		setBooleanOption(SourceMapFieldFactory.SHOW_IDENTIFIER_OPTION_NAME, false);
		ListingTextField textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_NAME + ":1 (2)", textField.getText());

		setBooleanOption(SourceMapFieldFactory.SHOW_IDENTIFIER_OPTION_NAME, true);
		textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_NAME + ":1 (2) [no id]", textField.getText());
	}

	@Test
	public void testShowInfoAtAllAddresses() throws Exception {
		setBooleanOption(SourceMapFieldFactory.SHOW_FILENAME_ONLY_OPTION_NAME, false);

		Address addr = entryPoint.next();
		Instruction inst = program.getListing().getInstructionAt(addr);
		assertEquals(2, inst.getLength());
		Instruction testInst = inst.getNext();
		Address testAddr = testInst.getAddress();

		int txID = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, addr, 5);
		}
		finally {
			program.endTransaction(txID, true);
		}
		setBooleanOption(SourceMapFieldFactory.SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, true);
		ListingTextField textField = getTextField(testAddr);
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_PATH + ":1 (5)", textField.getText());

		setBooleanOption(SourceMapFieldFactory.SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, false);
		assertFalse(cb.goToField(testAddr, SourceMapFieldFactory.FIELD_NAME, ROW, COLUMN));
	}

	@Test
	public void testOffcutSourceMapEntries() throws Exception {
		setBooleanOption(SourceMapFieldFactory.SHOW_FILENAME_ONLY_OPTION_NAME, false);
		Address addr = entryPoint.next();
		Instruction inst = program.getListing().getInstructionAt(addr);
		assertEquals(2, inst.getLength());
		Address testAddr = inst.getAddress().next();
		int txID = program.startTransaction("adding source map entry");
		try {
			sourceManager.addSourceMapEntry(source1, 1, testAddr, 1);
		}
		finally {
			program.endTransaction(txID, true);
		}

		setBooleanOption(SourceMapFieldFactory.SHOW_INFO_AT_ALL_ADDRESSES_OPTION_NAME, true);
		ListingTextField textField = getTextField(inst.getAddress());
		assertEquals(1, textField.getNumRows());
		assertEquals(SOURCE1_PATH + ":1 (1)", textField.getText());
		assertEquals(SourceMapFieldFactory.OFFCUT_COLOR,
			textField.getFieldElement(0, 0).getColor(0));
	}

	@Test
	public void testMaxNumEntries() throws Exception {

		int txID = program.startTransaction("adding source map entries");
		try {
			sourceManager.addSourceMapEntry(source1, 1, entryPoint, 1);
			sourceManager.addSourceMapEntry(source2, 2, entryPoint, 1);
		}
		finally {
			program.endTransaction(txID, true);
		}
		ListingTextField textField = getTextField(entryPoint);
		assertEquals(2, textField.getNumRows());

		SwingUtilities.invokeAndWait(() -> fieldOptions
				.setInt(SourceMapFieldFactory.MAX_ENTRIES_PER_ADDRESS_OPTION_NAME, 1));
		waitForSwing();
		cb.updateNow();

		textField = getTextField(entryPoint);
		assertEquals(1, textField.getNumRows());
	}

	@Test
	public void testFieldLocationSourceMapEntry() throws AddressOverflowException, LockException {
		int txID = program.startTransaction("adding source map entries");
		SourceMapEntry entry1 = null;
		SourceMapEntry entry2 = null;
		try {
			entry1 = sourceManager.addSourceMapEntry(source1, 1, entryPoint, 2);
			entry2 = sourceManager.addSourceMapEntry(source2, 3, entryPoint, 2);
		}
		finally {
			program.endTransaction(txID, true);
		}
		ListingTextField textField = getTextField(entryPoint);
		FieldFactory fieldFactory = textField.getFieldFactory();
		SourceMapFieldLocation one =
			(SourceMapFieldLocation) fieldFactory.getProgramLocation(0, 0, textField);
		assertEquals(entry1, one.getSourceMapEntry());

		SourceMapFieldLocation two =
			(SourceMapFieldLocation) fieldFactory.getProgramLocation(1, 0, textField);
		assertEquals(entry2, two.getSourceMapEntry());
	}

	private void init() throws Exception {
		builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
		sourceManager = program.getSourceFileManager();
		int txId = program.startTransaction("adding source files");
		source1 = new SourceFile(SOURCE1_PATH);
		source2 = new SourceFile(SOURCE2_PATH);
		try {
			assertTrue(sourceManager.addSourceFile(source1));
			assertTrue(sourceManager.addSourceFile(source2));
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	private void setBooleanOption(final String name, boolean value) throws Exception {
		SwingUtilities.invokeAndWait(() -> fieldOptions.setBoolean(name, value));
		waitForSwing();
		cb.updateNow();
	}

	private ListingTextField getTextField(Address address) {
		assertTrue(cb.goToField(address, SourceMapFieldFactory.FIELD_NAME, ROW, COLUMN));
		ListingTextField tf = (ListingTextField) cb.getCurrentField();
		return tf;
	}

}
