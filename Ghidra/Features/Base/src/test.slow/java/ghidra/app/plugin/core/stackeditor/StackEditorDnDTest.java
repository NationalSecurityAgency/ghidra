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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.*;

import ghidra.app.plugin.core.compositeeditor.CompositeEditorModelAdapter;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

public class StackEditorDnDTest extends AbstractStackEditorTest {

	private StatusListener myListener = new StatusListener();

	public StackEditorDnDTest() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		init(SIMPLE_STACK);

		model.addCompositeEditorModelListener(myListener);
	}

	private class StatusListener extends CompositeEditorModelAdapter {

		private List<String> messages = new ArrayList<>();

		@Override
		public void statusChanged(String message, boolean beep) {
			messages.add(message);
		}
	}

	@Override
	@After
	public void tearDown() throws Exception {
		cleanup();
		super.tearDown();
	}

	@Test
	public void testDragNDropAddLargerNoFit() throws Exception {

		assertEquals(20, model.getNumComponents());
		assertEquals(0x1e, model.getLength());

		DataType newType = programDTM.getDataType("/double");
		assertNotNull(newType);

		DataType existingStackType = getDataType(1);
		DataType tableType = getDataTypeAtRow(1);
		assertTrue(existingStackType.isEquivalent(tableType));

		addAtPoint(newType, 1, 0);
		assertEquals(20, model.getNumComponents());
		assertEquals(0x1e, model.getLength());

		DataType newStackType = getDataType(1);
		assertSame("Type should not have been replaced", existingStackType, newStackType);

		String expectedErrorMessage = "double doesn't fit within 4 bytes, need 8 bytes";
		if (!Objects.equals(expectedErrorMessage, model.getStatus())) {

			Msg.debug(this, "status message is not as expected.  Actual status messages found: ");
			Msg.debug(this, myListener.messages);
		}

		assertEquals(expectedErrorMessage, model.getStatus());
	}

	@Test
	public void testDragNDropAddDifferentTypes() throws Exception {
		env.showTool();
		int dtCol = model.getDataTypeColumn();
		DataType dt;
		assertEquals(20, model.getNumComponents());

		dt = stackModel.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		addAtPoint(dt, 0, 0);
		assertEquals(23, model.getNumComponents());
		assertCellString("byte", 0, dtCol);
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		dt = stackModel.getOriginalDataTypeManager().getDataType("/dword");
		assertNotNull(dt);
		addAtPoint(dt, 4, 0);
		assertEquals(20, model.getNumComponents());
		assertCellString("dword", 4, dtCol);
		assertTrue(getDataType(4).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(4).getLength());

		final DataType dt3 = dtmService.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt3);
		addAtPoint(dt3, 6, 0);
		assertEquals(17, model.getNumComponents());
		assertCellString("pointer", 6, dtCol);
		assertTrue(getDataType(6) instanceof Pointer);
		assertNull(((Pointer) getDataType(6)).getDataType());
		assertEquals(dt.getLength(), model.getComponent(6).getLength());

		addAtPoint(dt, 6, 0);
		assertEquals(17, model.getNumComponents());
		assertTrue(getDataType(6) instanceof Pointer);
		assertCellString("dword *", 6, dtCol);
		assertTrue(((Pointer) getDataType(6)).getDataType().isEquivalent(dt));
		assertEquals(4, model.getComponent(6).getLength());

		addAtPoint(dt3, 6, 0);
		assertEquals(17, model.getNumComponents());
		assertTrue(getDataType(6) instanceof Pointer);
		assertCellString("dword * *", 6, dtCol);
		assertTrue(((Pointer) getDataType(6)).getDataType().isEquivalent(new PointerDataType(dt)));
		assertEquals(4, model.getComponent(6).getLength());
	}

	@Test
	public void testDragNDropAddFirstMiddleLast() throws Exception {
		DataType dt;
		assertEquals(20, model.getNumComponents());

		dt = stackModel.getOriginalDataTypeManager().getDataType("/word");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(22, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		addAtPoint(dt, 10, 3);
		assertEquals(21, model.getNumComponents());
		assertTrue(getDataType(10).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(10).getLength());

		addAtPoint(dt, model.getNumComponents() - 1, 3);
		assertEquals(23, model.getNumComponents());
		assertTrue(getDataType(19).isEquivalent(dt));
	}

	@Test
	public void testDragNDropDynamic() throws Exception {
		env.showTool();
		int num = model.getNumComponents();
		int len = model.getLength();
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/PE");
		assertNotNull(dt);
		assertEquals("", model.getStatus());
		addAtPoint(dt, 15, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Factory data types are not allowed in a composite data type.",
			model.getStatus());

	}

	@Test
	public void testDragNDropAddSameSize() throws Exception {

		DataType dt;

		assertEquals(20, model.getNumComponents());
		assertEquals(0x1e, model.getLength());

		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);
		addAtPoint(dt, 1, 0);
		assertEquals(20, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(1).getLength());
		assertEquals(0x1e, model.getLength());
	}

	@Test
	public void testDragNDropAddSmaller() throws Exception {
		DataType dt;

		assertEquals(20, model.getNumComponents());
		assertEquals(0x1e, model.getLength());

		dt = programDTM.getDataType("/byte");
		DataType dt19 = getDataType(19);
		assertNotNull(dt);
		addAtPoint(dt, 18, 0);
		assertEquals(21, model.getNumComponents());
		assertTrue(getDataType(18).isEquivalent(dt));
		assertTrue(getDataType(19).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(20).isEquivalent(dt19));
		assertEquals(dt.getLength(), model.getComponent(18).getLength());
		assertEquals(0x1e, model.getLength());
	}

	@Test
	public void testDragNDropAddPointerAndConsume() throws Exception {

		int len = model.getLength();
		assertEquals("", model.getStatus());
		assertEquals(20, model.getNumComponents());
		DataType dt1 = getDataType(1);
		assertTrue(dt1.isEquivalent(DataType.DEFAULT));

		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 1, 0);

		assertEquals(17, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

}
