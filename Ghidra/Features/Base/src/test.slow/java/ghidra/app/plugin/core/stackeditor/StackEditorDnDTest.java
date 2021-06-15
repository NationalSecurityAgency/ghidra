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

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.data.*;

public class StackEditorDnDTest extends AbstractStackEditorTest {

	public StackEditorDnDTest() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		init(SIMPLE_STACK);
	}

	@Test
	public void testDragNDropAddDifferentTypes() throws Exception {
		env.showTool();
		try {
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
			assertTrue(
				((Pointer) getDataType(6)).getDataType().isEquivalent(new PointerDataType(dt)));
			assertEquals(4, model.getComponent(6).getLength());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testDragNDropAddFirstMiddleLast() throws Exception {
		try {
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
			assertEquals(dt.getLength(), model.getComponent(19).getLength());
		}
		finally {
			cleanup();
		}
	}

//	public void testDragNDropQWordOnFloat() throws Exception {
//		try {
//			DataType dt;
//			int num = model.getNumComponents();
//
//			assertEquals("Float", getDataType(4).getName());
//			dt = model.getOriginalDataTypeManager().findDataType("/QWord");
//			assertNotNull(dt);
//
//			addAtPoint(dt,4,3);
//
//			assertEquals(num, model.getNumComponents());
//			assertEquals("QWord", getDataType(4).getName());
//			assertTrue(getDataType(4).isEquivalent(dt));
//			assertEquals(dt.getLength(), model.getComponent(4).getLength());
//		}
//		finally {
//	cleanup();
//		}
//	}
//
//	public void testDragNDropOnPointer() throws Exception {
//		try {
//			DataType dt;
//			int num = model.getNumComponents();
//
//			int origLen = model.getComponent(2).getLength();
//			DataType origDt = getDataType(2);
//			assertEquals("Pointer", origDt.getName());
//			dt = model.getOriginalDataTypeManager().findDataType("/Byte");
//			assertNotNull(dt);
//
//			addAtPoint(dt,2,3);
//
//			assertEquals(num, model.getNumComponents());
//			assertEquals("Byte *", getDataType(2).getName());
//			assertTrue(((Pointer)getDataType(2)).getDataType().isEquivalent(dt));
//			assertEquals(origLen, model.getComponent(2).getLength());
//
//			dt = model.getOriginalDataTypeManager().findDataType("/String");
//			addAtPoint(dt,2,3);
//
//			assertEquals(num, model.getNumComponents());
//			assertEquals("String *", getDataType(2).getName());
//			assertTrue(((Pointer)getDataType(2)).getDataType().isEquivalent(dt));
//			assertEquals(origLen, model.getComponent(2).getLength());
//		}
//		finally {
//	cleanup();
//		}
//	}
//
//	public void testDragNDropPointerOnByte() throws Exception {
//		env.showTool();
//		NumberInputDialog dialog;
//		try {
//			int num = model.getNumComponents();
//
//			DataType origDt = getDataType(0);
//			assertEquals("Byte", origDt.getName());
//			final DataType dt = model.getOriginalDataTypeManager().findDataType("/Pointer");
//			assertNotNull(dt);
//
//			addAtPoint(dt,0,3);
//			waitForPostedSwingRunnables();
//			dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//			assertNotNull(dialog);
//			okInput(dialog, 2);
//			dialog.dispose();
//			dialog = null;
//			assertEquals(num, model.getNumComponents());
//			assertEquals("Byte *", getDataType(0).getName());
//			assertTrue(((Pointer)getDataType(0)).getDataType().isEquivalent(origDt));
//			assertEquals(2, model.getComponent(0).getLength());
//			assertEquals(-1, getDataType(0).getLength());
//		}
//		finally {
//			dialog = null;
//	cleanup();
//		}
//	}
//
//	public void testDragNDropPointerOnPointer() throws Exception {
//		try {
//			int num = model.getNumComponents();
//
//			DataType origDt = getDataType(5);
//			assertEquals("simpleStructure *", origDt.getName());
//			final DataType dt = model.getOriginalDataTypeManager().findDataType("/Pointer");
//			assertNotNull(dt);
//
//			addAtPoint(dt,5,3);
//			assertEquals(num, model.getNumComponents());
//			assertEquals("simpleStructure * *", getDataType(5).getName());
//			assertTrue(((Pointer)getDataType(5)).getDataType().isEquivalent(origDt));
//			assertEquals(4, model.getComponent(5).getLength());
//			assertEquals(-1, getDataType(5).getLength());
//		}
//		finally {
//	cleanup();
//		}
//	}
//
//	public void testDragNDropAddToContiguous() throws Exception {
//		try {
//			DataType dt = model.getOriginalDataTypeManager().findDataType("/Word");
//			int num = model.getNumComponents();
//			DataType dt3 = getDataType(3);
//			DataType dt15 = getDataType(15);
//			model.setSelection(new int[] {4,5,6,7,8,9,10,11,12,13,14});
//			addAtPoint(dt,5,0);
//			checkSelection(new int[] {4});
//			assertEquals(num-10, model.getNumComponents());
//			assertEquals(1, model.getNumSelectedComponents());
//			assertTrue(dt3.isEquivalent(getDataType(3)));
//			assertTrue(dt.isEquivalent(getDataType(4)));
//			assertEquals(dt15, getDataType(5));
//		}
//		finally {
//	cleanup();
//		}
//	}
//
//	public void testDragNDropAddToNonContiguous() throws Exception {
//		try {
//			DataType dt = model.getOriginalDataTypeManager().findDataType("/DWord");
//			int num = model.getNumComponents();
//			DataType dt3 = getDataType(3);
//			DataType dt4 = getDataType(4);
//			DataType dt5 = getDataType(5);
//			DataType dt6 = getDataType(6);
//			DataType dt8 = getDataType(8);
//			DataType dt9 = getDataType(9);
//			DataType dt10 = getDataType(10);
//			DataType dt15 = getDataType(15);
//			model.setSelection(new int[] {4,5,6,7,8,11,12,13,14});
//			addAtPoint(dt,5,0);
//			checkSelection(new int[] {4,7,8,9,10});
//			assertEquals(num-4, model.getNumComponents());
//			assertEquals(5, model.getNumSelectedComponents());
//			assertEquals(dt3, getDataType(3));
//			assertTrue(dt.isEquivalent(getDataType(4)));
//			assertEquals(dt9, getDataType(5));
//			assertEquals(dt10, getDataType(6));
//			assertEquals(dt15, getDataType(11));
//		}
//		finally {
//	cleanup();
//		}
//	}
//
	@Test
	public void testDragNDropDynamic() throws Exception {
		env.showTool();
		try {
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
		finally {
			cleanup();
		}
	}

//	public void testCancelDragNDropAddPointer() throws Exception {
//		try {
//			DataType dt = plugin.getBuiltInDataTypesManager().findDataType("/Pointer");
//			assertNotNull(dt);
//
//			int num = model.getNumComponents();
//			int len = model.getLength();
//			assertEquals("", model.getStatus());
//			DataType dt1 = getDataType(1);
//			assertTrue(dt1.isEquivalent(new WordDataType()));
//			addAtPoint(dt,1,0);
//			dialog = (NumberInputDialog)env.waitForDialog(NumberInputDialog.class, 1000);
//			assertNotNull(dialog);
//			cancelInput(dialog, 4);
//			dialog.dispose();
//			dialog = null;
//			assertEquals(num, model.getNumComponents());
//			assertEquals(len, model.getLength());
//			assertEquals(getDataType(1), dt1);
//			assertEquals(2, getDataType(1).getLength());
//			assertEquals(2, model.getComponent(1).getLength());
//
//		}
//		finally {
//	cleanup();
//		}
//	}
//
//	public void testDragNDropAddPointer() throws Exception {
//		try {
//			DataType dt = plugin.getBuiltInDataTypesManager().findDataType("/Pointer");
//			assertNotNull(dt);
//
//			int num = model.getNumComponents();
//			int len = model.getLength();
//			assertEquals("", model.getStatus());
//			DataType dt1 = getDataType(1);
//			assertTrue(dt1.isEquivalent(new WordDataType()));
//			addAtPoint(dt,1,0);
//			dialog = (NumberInputDialog)env.waitForDialog(NumberInputDialog.class, 1000);
//			assertNotNull(dialog);
//			okInput(dialog, 4);
//			dialog.dispose();
//			dialog = null;
//			assertEquals(num, model.getNumComponents());
//			assertEquals(len, model.getLength());
//			assertEquals("Word *", getDataType(1).getName());
//			assertTrue(((Pointer)getDataType(1)).getDataType().isEquivalent(dt1));
//			assertEquals(-1, getDataType(1).getLength());
//			assertEquals(4, model.getComponent(1).getLength());
//
//		}
//		finally {
//	cleanup();
//		}
//	}
//
	@Test
	public void testDragNDropAddSameSize() throws Exception {
		try {
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
		finally {
			cleanup();
		}
	}

//	public void testDragNDropConsumeAll() throws Exception {
//		try {
//			DataType dt;
//			model.clearComponents(new int[] {1,2,3});
//
//			assertEquals(12, model.getNumComponents());
//			assertEquals(29, model.getLength());
//
//			dt = programDTM.findDataType("/double");
//			assertNotNull(dt);
//			addAtPoint(dt,0,0);
//			assertEquals(5, model.getNumComponents());
//			assertEquals(29, model.getLength());
//			assertTrue(getDataType(0).isEquivalent(dt));
//			assertEquals(dt.getLength(), model.getComponent(0).getLength());
//		}
//		finally {
//			cleanup();
//		}
//	}
//
	@Test
	public void testDragNDropAddLargerNoFit() throws Exception {
		try {
			DataType dt;

			assertEquals(20, model.getNumComponents());
			assertEquals(0x1e, model.getLength());

			dt = programDTM.getDataType("/double");
			DataType dt1 = getDataType(1);
			assertNotNull(dt);
			addAtPoint(dt, 1, 0);
			assertEquals(20, model.getNumComponents());
			assertTrue(getDataType(1).isEquivalent(dt1));
			assertEquals(dt1.getLength(), model.getComponent(1).getLength());
			assertEquals(0x1e, model.getLength());
			assertEquals("double doesn't fit within 4 bytes, need 8 bytes", model.getStatus());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testDragNDropAddSmaller() throws Exception {
		try {
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
		finally {
			cleanup();
		}
	}

	@Test
	public void testDragNDropAddPointerAndConsume() throws Exception {
		try {
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
		finally {
			cleanup();
		}
	}

}
