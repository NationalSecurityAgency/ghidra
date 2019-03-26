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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.InvalidInputException;

public class StorageEditorModelTest extends AbstractGenericTest {

	protected static final int REQUIRE_SIZE = 8;
	protected StorageAddressModel model;
	private boolean dataChangeCalled;
	protected Function fun;
	protected AddressSpace stackSpace;
	protected ProgramDB program;

	protected final String testRegName;
	protected final String languageId;

	public StorageEditorModelTest() {
		this(ProgramBuilder._X86, "EAX");
	}

	protected StorageEditorModelTest(String languageId, String testRegName) {
		super();
		this.languageId = languageId;
		this.testRegName = testRegName;
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestProgram", languageId);
		builder.createMemory("block1", "1000", 1000);
		fun = builder.createEmptyFunction("bob", "1000", 20, new VoidDataType());

		program = builder.getProgram();
		stackSpace = program.getAddressFactory().getStackSpace();
		createStorageModel(REQUIRE_SIZE, 4, false);
	}

	protected void createStorageModel(int requiredStorage, int currentStorage,
			boolean unconstrained) throws InvalidInputException {
		Address address = stackSpace.getAddress(4);
		VariableStorage storage = new VariableStorage(program, address, currentStorage);

		model = new StorageAddressModel(program, storage,
			new ModelChangeListener() {

				@Override
				public void dataChanged() {
					dataChangeCalled = true;
				}

				@Override
				public void tableRowsChanged() {
					// nothing here
				}

			});
		model.setRequiredSize(requiredStorage, unconstrained);

	}

	protected void createStorageModel(int requiredStorage, boolean unconstrained) {

		model = new StorageAddressModel(program, VariableStorage.UNASSIGNED_STORAGE,
			new ModelChangeListener() {

				@Override
				public void dataChanged() {
					dataChangeCalled = true;
				}

				@Override
				public void tableRowsChanged() {
					// nothing here
				}

			});
		model.setRequiredSize(requiredStorage, unconstrained);
	}

	@Test
	public void testSizeCheck() {
		assertEquals(4, model.getCurrentSize());
		assertTrue(model.isValid());
		assertEquals("Warning: Not enough storage space allocated", model.getStatusText());
		VarnodeInfo varnode = model.getVarnodes().get(0);

		model.setVarnode(varnode, varnode.getAddress(), 12);
		assertTrue(model.isValid());
		assertEquals("Warning: Too much storage space allocated", model.getStatusText());

		model.setVarnode(varnode, varnode.getAddress(), REQUIRE_SIZE);
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());

		// test unconstrained
		createStorageModel(REQUIRE_SIZE, true);

		assertEquals(0, model.getCurrentSize());
		assertTrue(model.isValid());
		assertEquals("No storage has been allocated", model.getStatusText());

		model.addVarnode();
		varnode = model.getVarnodes().get(0);
		model.setVarnodeType(varnode, VarnodeType.Stack);
		model.setVarnode(varnode, stackSpace.getAddress(4), 4);
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());

		model.setVarnode(varnode, varnode.getAddress(), 12);
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());
	}

	@Test
	public void testAddStorage() {
		assertEquals(1, model.getVarnodes().size());
		dataChangeCalled = false;
		model.addVarnode();
		waitForPostedSwingRunnables();
		assertTrue(dataChangeCalled);

		assertEquals(2, model.getVarnodes().size());
		List<VarnodeInfo> varnodes = model.getVarnodes();
		VarnodeInfo varnodeInfo = varnodes.get(1);
		assertEquals(VarnodeType.Register, varnodeInfo.getType());
		assertEquals(null, varnodeInfo.getAddress());
		assertEquals(null, varnodeInfo.getSize());
		assertEquals(1, model.getSelectedVarnodeRows().length);
		assertEquals(1, model.getSelectedVarnodeRows()[0]);
	}

	@Test
	public void testRemove() {
		model.setSelectedVarnodeRows(new int[] { 0 });
		assertTrue(model.canRemoveVarnodes());

		model.addVarnode();
		assertEquals(1, model.getSelectedVarnodeRows()[0]);
		assertTrue(model.canRemoveVarnodes());

		model.setSelectedVarnodeRows(new int[] { 0 });
		dataChangeCalled = false;
		model.removeVarnodes();
		waitForPostedSwingRunnables();
		assertTrue(dataChangeCalled);

		List<VarnodeInfo> varnodes = model.getVarnodes();
		assertEquals(1, varnodes.size());
		VarnodeInfo varnodeInfo = varnodes.get(0);
		assertEquals(VarnodeType.Register, varnodeInfo.getType());

	}

	@Test
	public void testRemoveAll() {
		model.addVarnode();
		assertTrue(model.canRemoveVarnodes());
		model.setSelectedVarnodeRows(new int[] { 0, 1 });
		assertTrue(model.canRemoveVarnodes());
		model.removeVarnodes();

		waitForPostedSwingRunnables();
		assertTrue(dataChangeCalled);

		List<VarnodeInfo> varnodes = model.getVarnodes();
		assertEquals(0, varnodes.size());
	}

	@Test
	public void testMoveUpDownEnablement() {
		model.addVarnode();
		model.addVarnode();

		// no selection, both buttons disabled
		model.setSelectedVarnodeRows(new int[0]);
		assertTrue(!model.canMoveVarnodeUp());
		assertTrue(!model.canMoveVarnodeDown());

		// multiple selection, both buttons disabled
		model.setSelectedVarnodeRows(new int[] { 0, 1 });
		assertTrue(!model.canMoveVarnodeUp());
		assertTrue(!model.canMoveVarnodeDown());

		// select the first row, up button disabled, down button enabled
		model.setSelectedVarnodeRows(new int[] { 0 });
		assertTrue(!model.canMoveVarnodeUp());
		assertTrue(model.canMoveVarnodeDown());

		// select the middle row, both buttons enabled
		model.setSelectedVarnodeRows(new int[] { 1 });
		assertTrue(model.canMoveVarnodeUp());
		assertTrue(model.canMoveVarnodeDown());

	}

	@Test
	public void testMoveUp() {
		model.addVarnode();

		List<VarnodeInfo> varnodes = model.getVarnodes();
		assertEquals(2, varnodes.size());
		assertEquals(VarnodeType.Stack, varnodes.get(0).getType());
		assertEquals(VarnodeType.Register, varnodes.get(1).getType());

		// select the last row
		model.setSelectedVarnodeRows(new int[] { 1 });

		model.moveSelectedVarnodeUp();

		varnodes = model.getVarnodes();
		assertEquals(2, varnodes.size());
		assertEquals(VarnodeType.Register, varnodes.get(0).getType());
		assertEquals(VarnodeType.Stack, varnodes.get(1).getType());
		// check the selected row moved up as well
		assertEquals(1, model.getSelectedVarnodeRows().length);
		assertEquals(0, model.getSelectedVarnodeRows()[0]);

		assertTrue(!model.canMoveVarnodeUp());
	}

	@Test
	public void testMoveDown() {
		model.addVarnode();

		List<VarnodeInfo> varnodes = model.getVarnodes();
		assertEquals(2, varnodes.size());
		assertEquals(VarnodeType.Stack, varnodes.get(0).getType());
		assertEquals(VarnodeType.Register, varnodes.get(1).getType());

		// select the first row
		model.setSelectedVarnodeRows(new int[] { 0 });

		model.moveSelectedVarnodeDown();

		varnodes = model.getVarnodes();
		assertEquals(2, varnodes.size());
		assertEquals(VarnodeType.Register, varnodes.get(0).getType());
		assertEquals(VarnodeType.Stack, varnodes.get(1).getType());
		// check the selected row moved down as well
		assertEquals(1, model.getSelectedVarnodeRows().length);
		assertEquals(1, model.getSelectedVarnodeRows()[0]);

		assertTrue(!model.canMoveVarnodeDown());
	}

	@Test
	public void testChangingTypeClearsAddressButKeepsSize() {
		VarnodeInfo varnode = model.getVarnodes().get(0);
		model.setVarnode(varnode, varnode.getAddress(), REQUIRE_SIZE);// make everything good to go
		assertTrue(model.isValid());
		assertEquals(VarnodeType.Stack, varnode.getType());
		assertNotNull(varnode.getAddress());
		assertEquals(8, varnode.getSize().intValue());

		model.setVarnodeType(varnode, VarnodeType.Register);
		assertNull(varnode.getAddress());
		assertEquals(8, varnode.getSize().intValue());
	}

	@Test
	public void testDuplicateStorageAddress() {
		VarnodeInfo varnode = model.getVarnodes().get(0);
		model.setVarnodeType(varnode, VarnodeType.Register);
		model.setVarnode(varnode, program.getRegister(testRegName).getAddress(), 4);

		model.addVarnode();
		varnode = model.getVarnodes().get(1);
		model.setVarnode(varnode, program.getRegister(testRegName).getAddress(), 2);
		assertTrue(!model.isValid());
		assertEquals("Row 1: Overlapping storage address used.", model.getStatusText());
	}

}
