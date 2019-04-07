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
package ghidra.app.plugin.core.navigation.locationreferences;

import static org.junit.Assert.*;

import java.util.*;

import javax.swing.table.TableColumnModel;

import org.junit.After;
import org.junit.Before;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.actions.AbstractFindReferencesDataTypeAction;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.FieldNameFieldLocation;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.TaskMonitor;

/**
 * A base class for use by tests that exercise various types of 
 * {@link LocationDescriptor}.
 */
public abstract class AbstractLocationReferencesTest extends AbstractProgramBasedTest {

	protected DockingActionIf showReferencesAction;
	protected ProgramBuilder builder;
	protected LocationReferencesPlugin locationReferencesPlugin;

	@Before
	public void setUp() throws Exception {
		initialize();

		locationReferencesPlugin = getPlugin(tool, LocationReferencesPlugin.class);
		showReferencesAction =
			getAction(locationReferencesPlugin, AbstractFindReferencesDataTypeAction.NAME);
	}

	@Override
	@After
	public void tearDown() {
		env.dispose();
	}

	@Override
	protected Program getProgram() throws Exception {
		builder = new ClassicSampleX86ProgramBuilder();
		ProgramDB p = builder.getProgram();
		configureProgram();
		return p;
	}

	private void configureProgram() throws Exception {

		//
		// Xrefs
		//
		builder.createMemoryCallReference("0x0100446f", "0x01001004");

		//
		// Labels
		//
		builder.createMemoryReference("0x010036ee", "0x010039fe", RefType.CONDITIONAL_JUMP,
			SourceType.USER_DEFINED);

		//
		// Arrays/Structures
		//		
		DataType type = new IntegerDataType();
		DataType pointer = new PointerDataType(type);
		ArrayDataType array = new ArrayDataType(pointer, 4, pointer.getLength());
		builder.applyDataType("0x01005500", array);

		StructureDataType struct = new StructureDataType("struct_in_array", 0);
		struct.add(new IntegerDataType(), "my_int", "comment 1");
		struct.add(new ByteDataType(), "my_byte", "comment 2");
		array = new ArrayDataType(struct, 4, struct.getLength());
		builder.applyDataType("0x01005520", array);

		struct = new StructureDataType("struct_containing_array", 0);
		array = new ArrayDataType(pointer, 4, pointer.getLength());
		struct.add(new ByteDataType(), "my_byte", "comment 1");
		struct.add(array, "my_array", "comment 2");
		builder.applyDataType("0x01005540", struct);

		// a value that does not point to valid memory
		builder.setBytes("0x01004480", "cc cc cc cc");
		builder.applyDataType("0x01004480", new PointerDataType());
	}

	protected void goTo(Address a, String fieldName) {
		int row = 0;
		int col = 0;
		assertTrue(codeBrowser.goToField(a, fieldName, row, col));
	}

	protected void goTo(Address a, String fieldName, int col) {
		int row = 0;
		assertTrue("Code Browser failed to go to " + a,
			codeBrowser.goToField(a, fieldName, row, col));
	}

	protected void goTo(FieldNameFieldLocation fieldLocation) {
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", fieldLocation, program));
	}

	protected void goToDataNameFieldAt(Address a) {
		openData(a);
		goTo(a, FieldNameFieldFactory.FIELD_NAME);
	}

	protected void goToDataNameFieldAt(Address a, int... pathElements) {

		doGoToDataNameFieldAt(a, pathElements);
	}

	private void doGoToDataNameFieldAt(Address a, int[] path) {
		openData(a);

		// note: the path here is 
		FieldNameFieldLocation location = new FieldNameFieldLocation(program, a, path, "name", 0);
		ProgramLocationPluginEvent event =
			new ProgramLocationPluginEvent("Test", location, program);
		tool.firePluginEvent(event);
	}

	protected void goToDataAddressField(Address a) {
		openData(a);
		goTo(a, AddressFieldFactory.FIELD_NAME);
	}

	protected void goToDataAddressField(Address a, int row) {
		openData(a);

		AddressFieldLocation location =
			new AddressFieldLocation(program, a, new int[] { row }, a.toString(), 0);
		ProgramLocationPluginEvent event =
			new ProgramLocationPluginEvent("Test", location, program);
		tool.firePluginEvent(event);
	}

	protected void goToDataMnemonicField(Address a) {
		openData(a);
		goToMnemonicField(a);
	}

	protected void goToMnemonicField(Address a) {
		goTo(a, MnemonicFieldFactory.FIELD_NAME);
	}

	protected void goToOperandField(Address a, int column) {
		int row = 0;
		assertTrue(codeBrowser.goToField(a, OperandFieldFactory.FIELD_NAME, row, column));
	}

	protected void goToOperandField(Address a) {
		goTo(a, OperandFieldFactory.FIELD_NAME);
	}

	protected void openData(Address a) {
		runSwing(() -> {
			ListingModel listingModel = codeBrowser.getListingModel();
			Listing listing = program.getListing();
			Data parent = listing.getDataContaining(a);
			assertNotNull(parent);
			listingModel.openAllData(parent, TaskMonitor.DUMMY);
		});
	}

	protected void openData(long address) {
		openData(addr(address));
	}

	protected void waitForTable() {
		LocationReferencesTableModel model = getTableModel();
		if (model == null) {
			return;
		}
		waitForTableModel(model);
	}

	protected GhidraTable getTable() {
		LocationReferencesProvider provider = getResultsProvider();
		if (provider == null) {
			return null; // assume no provider was launched
		}
		Object referencesPanel = getInstanceField("referencesPanel", provider);
		return (GhidraTable) getInstanceField("table", referencesPanel);
	}

	protected LocationReferencesTableModel getTableModel() {
		LocationReferencesProvider provider = getResultsProvider();
		if (provider == null) {
			return null; // assume no provider was launched
		}
		Object referencesPanel = getInstanceField("referencesPanel", provider);
		return (LocationReferencesTableModel) getInstanceField("tableModel", referencesPanel);
	}

	@SuppressWarnings("unchecked")
	// we know the type is correct until the code changes
	protected LocationReferencesProvider getResultsProvider() {
		List<LocationReferencesProvider> providerList =
			(List<LocationReferencesProvider>) getInstanceField("providerList",
				locationReferencesPlugin);
		if (providerList.size() == 0) {
			return null;
		}

		return providerList.get(0);
	}

	protected List<LocationReference> getReferences(LocationDescriptor locationDescriptor) {

		waitForTable();

		Accumulator<LocationReference> accumulator = new ListAccumulator<>();
		runSwing(() -> {
			try {
				locationDescriptor.getReferences(accumulator, TaskMonitor.DUMMY, false);
			}
			catch (CancelledException e) {
				// can't happen!
			}
		});

		List<LocationReference> list = new ArrayList<>(accumulator.get());
		return list;
	}

	protected List<Address> getReferenceAddresses(LocationDescriptor locationDescriptor) {

		List<Address> list = new ArrayList<>();
		List<LocationReference> references = getReferences(locationDescriptor);
		for (LocationReference locationReference : references) {
			list.add(locationReference.getLocationOfUse());
		}

		return list;
	}

	protected void assertNoReference(List<LocationReference> list, Address... unexpected) {

		for (Address addr : unexpected) {
			for (LocationReference ref : list) {
				if (ref.getLocationOfUse().equals(addr)) {
					fail("Did expect address in list of references - unexpected " + addr +
						"; found " + list);
				}
			}
		}
	}

	protected void assertContains(List<LocationReference> list, Address... expected) {

		if (list.size() != expected.length) {
			fail("Expected\n\t" + Arrays.toString(expected) + "\n\tfound:\n\t" + list);
		}

		for (Address addr : expected) {
			assertContainsAddr(list, addr);
		}
	}

	protected boolean assertContainsAddr(List<LocationReference> list, Address addr) {
		for (LocationReference ref : list) {
			if (ref.getLocationOfUse().equals(addr)) {
				return true;
			}
		}
		fail("Did not find expected address in list of references - expected " + addr + "; found " +
			list);
		return false;
	}

	protected void assertNoResults(String msg) {
		LocationReferencesProvider provider = getResultsProvider();
		assertNull(msg, provider);
	}

	protected void assertHasResults(String msg) {
		List<Address> referenceAddresses = getResultAddresses();
		assertFalse(msg, referenceAddresses.isEmpty());
	}

	protected void assertResultCount(int expected) {
		List<Address> referenceAddresses = getResultAddresses();
		assertEquals(expected, referenceAddresses.size());
	}

	protected void assertResultCount(String msg, int expected) {
		List<Address> referenceAddresses = getResultAddresses();
		assertEquals(msg, expected, referenceAddresses.size());
	}

	protected List<LocationReference> getResultLocations() {
		LocationReferencesProvider provider = getResultsProvider();
		LocationDescriptor descriptor = provider.getLocationDescriptor();
		List<LocationReference> references = getReferences(descriptor);
		return references;
	}

	protected List<Address> getResultAddresses() {
		LocationReferencesProvider provider = getResultsProvider();
		LocationDescriptor descriptor = provider.getLocationDescriptor();
		List<Address> addrs = getReferenceAddresses(descriptor);
		return addrs;
	}

	protected String getContextColumnValue(LocationReference rowObject) {
		LocationReferencesTableModel model = getTableModel();

		GhidraTable table = getTable();
		TableColumnModel columnModel = table.getColumnModel();
		int col = columnModel.getColumnIndex("Context");
		Object value = model.getColumnValueForRow(rowObject, col);
		return value.toString();
	}

	protected void search() {
		LocationReferencesProvider provider = getResultsProvider();
		if (provider != null) {
			// having a provider open implies we have already searched, which could cause
			// follow-on searches to be lost when providers are tabbed.
			closeProvider(provider);
		}

		performAction(showReferencesAction, getCodeViewerProvider(), true);
	}

	protected ComponentProvider getCodeViewerProvider() {
		return codeBrowser.getProvider();
	}

	protected Data createData(Address a, DataType dt) {

		int tx = program.startTransaction("Test");
		try {
			Data data =
				DataUtilities.createData(program, a, dt, 1, false, ClearDataMode.CHECK_FOR_SPACE);
			assertNotNull("Unable to apply data type at address: " + a, data);
			return data;
		}
		catch (Exception e) {
			failWithException("Unable to create data", e);
		}
		finally {
			program.endTransaction(tx, true);
		}

		return null; // can't get here
	}

	protected DataType getDataType(String name) {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		Iterator<DataType> allDataTypes = dataTypeManager.getAllDataTypes();
		DataType dataType = null;
		while (allDataTypes.hasNext()) {
			DataType currentDataType = allDataTypes.next();
			if (currentDataType.getDisplayName().equals(name)) {
				dataType = currentDataType;
				break;
			}
		}

		assertNotNull("Unable to locate a " + name + " DataType.", dataType);

		return dataType;
	}

	protected void createReference(Address from, Address to) {
		AddMemRefCmd addRefCommand =
			new AddMemRefCmd(from, to, RefType.READ, SourceType.USER_DEFINED, 0);
		boolean referenceAdded = applyCmd(program, addRefCommand);
		assertTrue("Unable to add reference to: " + to, referenceAdded);
	}

	protected void createByte(long address) {
		Address a = addr(address);
		CreateDataCmd cmd = new CreateDataCmd(a, new ByteDataType());
		assertTrue(applyCmd(program, cmd));
	}

}
