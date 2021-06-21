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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class UnionEditorDnDTest extends AbstractUnionEditorTest {

	@Test
	public void testDragNDropAddDifferentTypes() throws Exception {
		NumberInputDialog dialog;
		init(emptyUnion, pgmRootCat, false);
		DataType dt;

		assertEquals(0, model.getNumComponents());

		dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		addAtPoint(dt, 0, 0);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		dt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(dt);
		addAtPoint(dt, 1, 0);
		assertEquals(2, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(1).getLength());

		DataType dt3 = new Pointer32DataType();
		assertNotNull(dt3);
		addAtPoint(dt3, 2, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(2).isEquivalent(dt3));
		assertEquals(4, model.getComponent(2).getLength());

		DataType dt4 = model.getOriginalDataTypeManager().getDataType("/string");
		assertNotNull(dt4);
		addAtPoint(dt4, 2, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(2) instanceof Pointer);
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt4));
		assertEquals(4, model.getComponent(2).getLength());

		assertNotNull(dt4);
		addAtPoint(dt4, 3, 0);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 25);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(4, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt4));
		assertEquals(25, model.getComponent(3).getLength());
	}

	@Test
	public void testDragNDropInsertDifferentTypes() throws Exception {
		NumberInputDialog dialog;
		init(emptyUnion, pgmRootCat, false);

		DataType dt;

		assertEquals(0, model.getNumComponents());

		dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		insertAtPoint(dt, 0, 0);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		dt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(dt);
		insertAtPoint(dt, 0, 0);
		assertEquals(2, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		DataType dt3 = model.getOriginalDataTypeManager().getDataType("/undefined *32");
		assertNotNull(dt3);
		insertAtPoint(dt3, 0, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt3));
		assertEquals(dt3.getLength(), model.getComponent(0).getLength());

		DataType dt4 = model.getOriginalDataTypeManager().getDataType("/string");
		assertNotNull(dt4);
		insertAtPoint(dt4, 0, 0);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 25);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(4, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt4));
		assertEquals(25, model.getComponent(0).getLength());
	}

	@Test
	public void testDragNDropAddFirstMiddleLast() throws Exception {
		init(complexUnion, pgmTestCat, false);
		DataType dt;
		int num = model.getNumComponents();

		dt = model.getOriginalDataTypeManager().getDataType("/word");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		addAtPoint(dt, 10, 3);
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(10).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(10).getLength());

		addAtPoint(dt, num, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(num - 1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(num - 1).getLength());
	}

	@Test
	public void testDragNDropInsertFirstMiddleLast() throws Exception {
		init(complexUnion, pgmTestCat, false);
		DataType dt;
		int num = model.getNumComponents();

		dt = model.getOriginalDataTypeManager().getDataType("/word");
		assertNotNull(dt);

		insertAtPoint(dt, 0, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());

		insertAtPoint(dt, 10, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(10).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(10).getLength());

		insertAtPoint(dt, num, 3);
		num++;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(num - 1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(num - 1).getLength());
	}

	@Test
	public void testDragNDropQWordOnFloat() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		DataType dt;
		int num = model.getNumComponents();

		assertEquals("float", getDataType(4).getDisplayName());
		dt = model.getOriginalDataTypeManager().getDataType("/qword");
		assertNotNull(dt);

		addAtPoint(dt, 4, 3);

		assertEquals(num, model.getNumComponents());
		assertEquals("qword", getDataType(4).getDisplayName());
		assertTrue(getDataType(4).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(4).getLength());
	}

	@Test
	public void testDragNDropOnPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);
		DataType dt;
		int num = model.getNumComponents();

		int origLen = model.getComponent(2).getLength();
		DataType origDt = getDataType(2);
		assertEquals("undefined *", origDt.getDisplayName());
		dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);

		addAtPoint(dt, 2, 3);

		assertEquals(num, model.getNumComponents());
		assertEquals("byte *", getDataType(2).getDisplayName());
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt));
		assertEquals(origLen, model.getComponent(2).getLength());

		dt = model.getOriginalDataTypeManager().getDataType("/string");
		addAtPoint(dt, 2, 3);

		assertEquals(num, model.getNumComponents());
		assertEquals("string *", getDataType(2).getDisplayName());
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt));
		assertEquals(origLen, model.getComponent(2).getLength());
	}

	@Test
	public void testDragNDropPointerOnByte() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(0);
		assertEquals("byte", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer", getDataType(0).getDisplayName());
		assertNull(((Pointer) getDataType(0)).getDataType());
		assertEquals(4, model.getComponent(0).getLength());
		assertEquals(4, getDataType(0).getLength());
	}

	@Test
	public void testDragNDropPointer8OnByte() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(0);
		assertEquals("byte", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer8");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer8", getDataType(0).getDisplayName());
		assertNull(((Pointer) getDataType(0)).getDataType());
		assertEquals(1, model.getComponent(0).getLength());
		assertEquals(1, getDataType(0).getLength());
	}

	@Test
	public void testDragNDropPointer16OnByte() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(0);
		assertEquals("byte", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer16");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer16", getDataType(0).getDisplayName());
		assertNull(((Pointer) getDataType(0)).getDataType());
		assertEquals(2, model.getComponent(0).getLength());
		assertEquals(2, getDataType(0).getLength());
	}

	@Test
	public void testDragNDropPointer32OnByte() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(0);
		assertEquals("byte", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer32");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer32", getDataType(0).getDisplayName());
		assertNull(((Pointer) getDataType(0)).getDataType());
		assertEquals(4, model.getComponent(0).getLength());
		assertEquals(4, getDataType(0).getLength());
	}

	@Test
	public void testDragNDropPointer64OnByte() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(0);
		assertEquals("byte", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer64");
		assertNotNull(dt);

		addAtPoint(dt, 0, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer64", getDataType(0).getDisplayName());
		assertNull(((Pointer) getDataType(0)).getDataType());
		assertEquals(8, model.getComponent(0).getLength());
		assertEquals(8, getDataType(0).getLength());
	}

	@Test
	public void testDragNDropPointerOnPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(5);
		assertEquals("simpleStructure *", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		addAtPoint(dt, 5, 3);
		assertEquals(num, model.getNumComponents());
		assertEquals("simpleStructure * *", getDataType(5).getDisplayName());
		assertTrue(((Pointer) getDataType(5)).getDataType().isEquivalent(origDt));
		assertEquals(4, model.getComponent(5).getLength());
		assertEquals(4, getDataType(5).getLength());
	}

	@Test
	public void testDragNDropInsertPointerOnPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int num = model.getNumComponents();

		DataType origDt = getDataType(5);
		assertEquals("simpleStructure *", origDt.getDisplayName());

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer16");
		assertNotNull(dt);

		insertAtPoint(dt, 5, 3);

		assertEquals(num + 1, model.getNumComponents());
		assertEquals("pointer16", getDataType(5).getDisplayName());
		assertEquals("simpleStructure *", getDataType(6).getDisplayName());
		assertTrue(getDataType(6).isEquivalent(origDt));
		assertTrue(getDataType(5).isEquivalent(dt));
		assertEquals(2, model.getComponent(5).getLength());
		assertEquals(4, model.getComponent(6).getLength());
		assertEquals(2, getDataType(5).getLength());
		assertEquals(4, getDataType(6).getLength());
	}

	@Test
	public void testDragNDropInsertToContiguous() throws Exception {
		init(complexUnion, pgmTestCat, false);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/word");
		int num = model.getNumComponents();
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 });
		insertAtPoint(dt, 5, 0);
		checkSelection(new int[] { 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(11, model.getNumSelectedComponentRows());
		assertEquals(dt3, getDataType(3));
		assertEquals(dt4, getDataType(4));
		assertTrue(dt.isEquivalent(getDataType(5)));
		assertEquals(dt5, getDataType(6));
		assertEquals(dt15, getDataType(16));
	}

	@Test
	public void testDragNDropAddToContiguous() throws Exception {
		init(complexUnion, pgmTestCat, false);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/word");
		int num = model.getNumComponents();
		DataType dt3 = getDataType(3);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 });
		addAtPoint(dt, 5, 0);
		checkSelection(new int[] { 4 });
		assertEquals(num - 10, model.getNumComponents());
		assertEquals(1, model.getNumSelectedComponentRows());
		assertTrue(dt3.isEquivalent(getDataType(3)));
		Pointer innerPtr = (Pointer) ((Pointer) getDataType(4)).getDataType();
		assertTrue(dt.isEquivalent(innerPtr.getDataType()));
		assertEquals(dt15, getDataType(5));
	}

	@Test
	public void testDragNDropInsertToNonContiguous() throws Exception {
		init(complexUnion, pgmTestCat, false);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/dword");
		int num = model.getNumComponents();
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt8 = getDataType(8);
		DataType dt9 = getDataType(9);
		DataType dt10 = getDataType(10);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 4, 5, 6, 7, 8, 11, 12, 13, 14 });
		insertAtPoint(dt, 5, 0);
		checkSelection(new int[] { 4, 6, 7, 8, 9, 12, 13, 14, 15 });
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(9, model.getNumSelectedComponentRows());
		assertEquals(dt3, getDataType(3));
		assertEquals(dt4, getDataType(4));
		assertTrue(dt.isEquivalent(getDataType(5)));
		assertEquals(dt5, getDataType(6));
		assertEquals(dt8, getDataType(9));
		assertEquals(dt9, getDataType(10));
		assertEquals(dt10, getDataType(11));
		assertEquals(dt15, getDataType(16));
	}

	@Test
	public void testDragNDropAddToNonContiguous() throws Exception {
		init(complexUnion, pgmTestCat, false);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/dword");
		int num = model.getNumComponents();
		DataType dt2 = getDataType(2);
		DataType dt9 = getDataType(9);
		DataType dt10 = getDataType(10);
		DataType dt15 = getDataType(15);
		setSelection(new int[] { 3, 4, 5, 6, 7, 8, 11, 12, 13, 14 });
		addAtPoint(dt, 5, 0);
		checkSelection(new int[] { 3, 6, 7, 8, 9 });
		assertEquals(num - 5, model.getNumComponents());
		assertEquals(5, model.getNumSelectedComponentRows());
		assertEquals(dt2, getDataType(2));
		assertTrue(dt.isEquivalent(getDataType(3)));
		assertEquals(dt9, getDataType(4));
		assertEquals(dt10, getDataType(5));
		assertEquals(dt15, getDataType(10));
	}

	@Test
	public void testDragNDropUnionOnSelf() throws Exception {
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexUnion, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexUnion\" can't contain itself.", model.getStatus());
	}

	@Test
	public void testDragNDropSelfOnPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dt5 = getDataType(5);
		assertEquals("", model.getStatus());
		addAtPoint(complexUnion, 5, 0);
		assertEquals(num, model.getNumComponents());
		assertTrue(!dt5.isEquivalent(getDataType(5)));
		assertEquals(((Pointer) getDataType(5)).getDataType(), model.viewComposite);
		assertEquals(len, model.getLength());
		assertEquals("", model.getStatus());
	}

	@Test
	public void testDragNDropFactory() throws Exception {
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/PE");
		assertNotNull(dt);
		assertEquals("", model.getStatus());
		addAtPoint(dt, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Factory data types are not allowed in a composite data type.",
			model.getStatus());
	}

	@Test
	public void testDragNDropDynamic() throws Exception {
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataTypeManager builtInDTM = plugin.getBuiltInDataTypesManager();
		DataType dt = builtInDTM.getDataType("/GIF-Image");
		assertNotNull(dt);
		assertEquals("", model.getStatus());
		addAtPoint(dt, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Non-sizable Dynamic data types are not allowed in a composite data type.",
			model.getStatus());
	}

	@Test
	public void testDragNDropStructContainingEditType() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexStructure, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexStructure\" has \"simpleUnion\" within it.",
			model.getStatus());
	}

	@Test
	public void testDragNDropUnionContainingEditType() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		addAtPoint(complexUnion, model.getNumComponents(), 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("Data type \"complexUnion\" has \"simpleUnion\" within it.",
			model.getStatus());
	}

	@Test
	public void testDragNDropAddPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		DataType dt1 = getDataType(1);
		assertTrue(dt1.isEquivalent(new WordDataType()));

		addAtPoint(PointerDataType.dataType, 1, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());

		addAtPoint(StringDataType.dataType, 1, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("string *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(StringDataType.dataType));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());

		addAtPoint(PointerDataType.dataType, 1, 0);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("string * *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(
			new PointerDataType(StringDataType.dataType)));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testDragNDropInsertPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer");
		assertNotNull(dt);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		DataType dt1 = getDataType(1);
		assertTrue(dt1.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 1, 0);

		assertEquals(num + 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertTrue(getDataType(1) instanceof Pointer);
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertEquals(getDataType(2), dt1);
	}

	@Test
	public void testDragNDropInsertSizedPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		DataType dt = plugin.getBuiltInDataTypesManager().getDataType("/pointer32");
		assertNotNull(dt);

		int num = model.getNumComponents();
		int len = model.getLength();
		assertEquals("", model.getStatus());
		DataType dt1 = getDataType(1);
		assertTrue(dt1.isEquivalent(new WordDataType()));
		insertAtPoint(dt, 1, 0);

		assertEquals(num + 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals("pointer32", getDataType(1).getDisplayName());
		assertTrue(getDataType(1) instanceof Pointer);
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertEquals(getDataType(2), dt1);
	}

}
