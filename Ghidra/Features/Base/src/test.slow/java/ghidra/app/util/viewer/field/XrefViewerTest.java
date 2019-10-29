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

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.format.FieldHeader;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.XRefHeaderFieldLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.table.GhidraProgramTableModel;

/**
 * Tests that references are displayed correctly when selecting the XRef field in
 * the listing.
 *
 * Note: 	These tests are only concerned with functionality associated with double-clicking
 * 			the reference header field and bringing up the associated table, NOT the reference
 * 			information displayed directly in the listing.
 *
 */
public class XrefViewerTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String NESTED_STRUCT_ADDR = "100101b";
	private TestEnv env;
	private Program program;
	private PluginTool tool;
	private CodeBrowserPlugin cb;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);
		cb = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/**
	 * Verifies the display of references to data.
	 */
	@Test
	public void testViewReferencesToData() {
		doubleClickXRef("1001007", "XREF[2]: ");
		ComponentProvider comp = waitForComponentProvider(TableComponentProvider.class);
		TableComponentProvider<?> table = (TableComponentProvider<?>) comp;
		assertEquals(2, table.getModel().getRowCount());
	}

	/**
	 * Verifies the display of references to functions.
	 */
	@Test
	public void testViewReferencesToFunction() {
		doubleClickXRef("1001005", "XREF[1]: ");
		ComponentProvider comp = waitForComponentProvider(TableComponentProvider.class);
		TableComponentProvider<?> table = (TableComponentProvider<?>) comp;
		assertEquals(1, table.getModel().getRowCount());
	}

	/**
	 * Verifies that references inside of structures inside of structures, at the top-level
	 * address will be displayed correctly.
	 */
	@Test
	public void testViewReferencesInStructureInStructure() {
		createStructureInStructure();

		// First expand the structure.
		Address parentStructAddress = addr(NESTED_STRUCT_ADDR);

		goTo(tool, program, parentStructAddress);

		expandData();

		addDataXrefFieldsToListing();

		// We have 3 structure refs: 1 to the top-level parent, 1 to the nested structure, 1 to
		// the parent struct's 2 second element.  The top-level will report all 3 refs.  The
		// child structure will report only 2.
		doubleClickXRef("100101b", "XREF[1,2]: "); // parent structure XRef field
		assertTableXRefCount(3);

		doubleClickXRef("100101b", 0 /* second row at child structure */, "XREF[1,1]: ");
		assertTableXRefCount(2);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertTableXRefCount(int expectedRowCount) {
		ComponentProvider comp = waitForComponentProvider(TableComponentProvider.class);
		TableComponentProvider<?> provider = (TableComponentProvider<?>) comp;
		GhidraProgramTableModel<?> model = provider.getModel();
		waitForTableModel(model);
		int actualRowCount = runSwing(() -> provider.getModel().getRowCount());
		assertEquals(expectedRowCount, actualRowCount);
		runSwing(() -> provider.closeComponent()); // remove for follow-up checks
	}

	/**
	 * Adds the XRef and XRef Header fields from the Open Data category to the
	 * listing. These are not visible by default.
	 */
	private void addDataXrefFieldsToListing() {
		runSwing(() -> {
			cb.getListingPanel().showHeader(true);

			FieldHeader header = cb.getListingPanel().getFieldHeader();
			int index = header.indexOfTab("Open Data");
			header.setSelectedIndex(index);
			FieldFormatModel model = header.getHeaderTab().getModel();
			addField(model, "XRef Header", 6);
			addField(model, "XRef", 7);

			cb.getListingPanel().showHeader(false);
		});
	}

	/**
	 * Adds a listing field to the given model.
	 *
	 * @param model the model to updated
	 * @param fieldName the name of the field to add
	 * @param column the column where the field should be displayed
	 */
	private void addField(FieldFormatModel model, String fieldName, int column) {
		FieldFactory[] allFactories = model.getAllFactories();
		for (FieldFactory fieldFactory : allFactories) {
			if (fieldFactory.getFieldName().equals(fieldName)) {
				model.addFactory(fieldFactory, 0, column);
			}
		}
	}

	/*
	 * Builds a simple program that has the following attributes:
	 *
	 *  - reference to data
	 *  - reference to a function
	 *  - structure with an internal reference
	 *
	 * @return the new program
	 * @throws Exception
	 */
	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createEntryPoint("1001000", "entrypoint");
		builder.createEmptyFunction(null, "1001005", 40, null);
		builder.setBytes("1001005", "ff 74 24 04", true);
		builder.setBytes("10010a0", "ff 15 d4 10 00 01", true);

		builder.createMemoryReference("1001005", "1001007", RefType.DATA, SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001009", "1001007", RefType.DATA, SourceType.DEFAULT, 0);
		builder.createMemoryReadReference("1001009", "1001005");

		// structure at 100100b
		builder.createMemoryReference("1001005", "100100f", RefType.DATA, SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001002", "100100f", RefType.DATA, SourceType.DEFAULT, 0);

		return builder.getProgram();
	}

	private void createStructureInStructure() {
		int id = program.startTransaction("Structure");

		Structure struct = new StructureDataType("ParentStructure", 0);
		Structure child = new StructureDataType("ChildStructure", 0);
		child.add(new ByteDataType());
		child.add(new ByteDataType());

		struct.add(child);
		struct.add(new ByteDataType()); // a child below the first child structure

		CreateStructureCmd cmd = new CreateStructureCmd(struct, addr(NESTED_STRUCT_ADDR));

		cmd.applyTo(program);
		program.endTransaction(id, true);

		// structure at 100101b - create refs to the parent structure and to the
		// child structure (this will be offcut at the parent level), and an element below the
		// first child structure.
		builder.createMemoryReference("1001012", NESTED_STRUCT_ADDR, RefType.DATA,
			SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001013", "100101c", RefType.DATA, SourceType.DEFAULT, 0);
		builder.createMemoryReference("1001014", "100101d", RefType.DATA, SourceType.DEFAULT, 0);
	}

	private Address addr(String address) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getAddress(address);
	}

	private void doubleClickXRef(String addr, String expectedFieldText) {
		runSwing(() -> cb.goToField(addr(addr), "XRef Header", 0, 2));
		ListingField currentField = cb.getCurrentField();
		String actualText = currentField.getText();
		assertEquals("The Listing is not on the expected field", expectedFieldText, actualText);

		click(cb, 2);
		waitForSwing();
	}

	private void doubleClickXRef(String addr, int row, String expectedFieldText) {

		int[] path = new int[row + 1];
		for (int i = 0; i < row; i++) {
			path[i] = i;
		}

		XRefHeaderFieldLocation loc = new XRefHeaderFieldLocation(program, addr(addr), path, 0);
		ProgramLocationPluginEvent event = new ProgramLocationPluginEvent("Test", loc, program);
		tool.firePluginEvent(event);
		waitForSwing();

		ListingField currentField = cb.getCurrentField();
		String actualText = currentField.getText();
		assertEquals("The Listing is not on the expected field", expectedFieldText, actualText);

		click(cb, 2);
	}

	private void expandData() {
		DockingActionIf expand = getAction(cb, "Expand All Data");
		performAction(expand, cb.getProvider().getActionContext(null), true);
	}

}
