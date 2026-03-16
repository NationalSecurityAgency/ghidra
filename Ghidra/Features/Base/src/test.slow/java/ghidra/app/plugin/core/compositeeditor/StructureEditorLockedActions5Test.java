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

import java.util.List;

import org.junit.Test;

import ghidra.program.model.data.*;

public class StructureEditorLockedActions5Test extends AbstractStructureEditorTest {

	@Test
	public void testUnpackageComponentArray() throws Exception {

		program.withTransaction("Modify structures", () -> {

			complexStructure.setPackingEnabled(true);

			// Add zero-length component after component to be unpacked
			complexStructure.insert(12, new ArrayDataType(CharDataType.dataType, 0), 0, "z1", null);
			complexStructure.insert(13, new ArrayDataType(CharDataType.dataType, 0), 0, "z2", null);
		});

		init(complexStructure, pgmTestCat);

		Structure viewStruct =
			(Structure) model.getViewDataTypeManager().getResolvedViewComposite();

		List<DataTypeComponent> componentsAt96 = viewStruct.getComponentsContaining(96);
		assertEquals(3, componentsAt96.size());
		assertEquals("z1", componentsAt96.get(0).getFieldName());
		assertEquals("z2", componentsAt96.get(1).getFieldName());
		assertEquals("simpleStructure[3]", componentsAt96.get(2).getDataType().getName());

		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dt11 = getDataType(11);
		assertTrue(dt11 instanceof Array);
		DataType element = ((Array) dt11).getDataType();
		int elementLen = ((Array) dt11).getElementLength();
		setSelection(new int[] { 11 });
		assertEquals("string[5]", getDataType(11).getDisplayName());
		invoke(unpackageAction);

		waitForSwing();

		assertEquals(len, model.getLength());
		assertEquals(num + 4, model.getNumComponents());
		assertTrue(!getDataType(11).isEquivalent(simpleStructure));
		for (int i = 0; i < 5; i++) {
			DataTypeComponent dtc = model.getComponent(11 + i);
			DataType sdt = dtc.getDataType();
			assertTrue(sdt.isEquivalent(element));
			assertEquals("string", sdt.getDisplayName());
			assertEquals(elementLen, dtc.getLength());
		}

		componentsAt96 = viewStruct.getComponentsContaining(96);
		assertEquals(3, componentsAt96.size());
		assertEquals("z1", componentsAt96.get(0).getFieldName());
		assertEquals("z2", componentsAt96.get(1).getFieldName());
		assertEquals("simpleStructure[3]", componentsAt96.get(2).getDataType().getName());
	}

	@Test
	public void testUnpackageComponentStructure() throws Exception {

		program.withTransaction("Modify simpleStruct", () -> {

			complexStructure.setPackingEnabled(true);

			simpleStructure.setPackingEnabled(true); // simplifies adding bitfields
			simpleStructure.delete(1); // remove word component where bitfields will be inserted
			simpleStructure.insertBitField(1, 2, 0, WordDataType.dataType, 3, "bf012", null);
			simpleStructure.insertBitField(1, 2, 3, WordDataType.dataType, 2, "bf34", null);
			simpleStructure.insertBitField(1, 2, 7, WordDataType.dataType, 1, "bf7", null);

			// Add zero-length component after component to be unpacked
			complexStructure.insert(18, new ArrayDataType(CharDataType.dataType, 0), 0, "z1", null);
			complexStructure.insert(19, new ArrayDataType(CharDataType.dataType, 0), 0, "z2", null);
		});

		waitForSwing();

		init(complexStructure, pgmTestCat);

		Structure viewStruct =
			(Structure) model.getViewDataTypeManager().getResolvedViewComposite();

		List<DataTypeComponent> componentsAt340 = viewStruct.getComponentsContaining(340);
		assertEquals(3, componentsAt340.size());
		assertEquals("z1", componentsAt340.get(0).getFieldName());
		assertEquals("z2", componentsAt340.get(1).getFieldName());
		assertEquals("refStructure *32", componentsAt340.get(2).getDataType().getName());

		int num = model.getNumComponents();
		int len = model.getLength();
		int numComps = simpleStructure.getNumComponents();
		setSelection(new int[] { 17 });
		assertEquals("simpleStructure", getDataType(17).getDisplayName());
		invoke(unpackageAction);

		assertEquals(len, model.getLength());
		assertEquals(num + numComps - 1, model.getNumComponents());
		assertTrue(!getDataType(17).isEquivalent(simpleStructure));
		for (int i = 0; i < numComps; i++) {
			DataTypeComponent dtc = getComponent(17 + i);
			DataType sdt = simpleStructure.getComponent(i).getDataType();
			assertTrue("type mismatch: " + sdt.getDisplayName() + " at " + dtc.getOffset(),
				dtc.getDataType().isEquivalent(sdt));
			assertEquals("name mismatch: " + sdt.getDisplayName() + " at " + dtc.getOffset(),
				sdt.getDisplayName(), dtc.getDataType().getDisplayName());
		}

		// When packing enabled, existing zero-length components moved based upon their char alignment of 1
		List<DataTypeComponent> componentsAt337 = viewStruct.getComponentsContaining(337);
		assertEquals(2, componentsAt337.size());
		assertEquals("z1", componentsAt337.get(0).getFieldName());
		assertEquals("z2", componentsAt337.get(1).getFieldName());

		componentsAt340 = viewStruct.getComponentsContaining(340);
		assertEquals(1, componentsAt340.size());
		assertEquals("refStructure *32", componentsAt340.get(0).getDataType().getName());

	}
}
