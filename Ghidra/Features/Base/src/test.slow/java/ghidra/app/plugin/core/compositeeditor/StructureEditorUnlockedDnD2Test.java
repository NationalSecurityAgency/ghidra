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

import org.junit.Before;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class StructureEditorUnlockedDnD2Test extends AbstractStructureEditorTest {

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	protected void init(Structure dt, Category cat) {
		super.init(dt, cat, false);
		runSwing(() -> {
//				model.setLocked(false);
		});
//		assertTrue(!model.isLocked());
	}

	@Test
	public void testDragNDropAddDifferentTypes() throws Exception {
		NumberInputDialog dialog;
		init(emptyStructure, pgmRootCat);
		DataType dt;

		assertEquals(0, model.getNumComponents());

		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);
		addAtPoint(dt, 0, 0);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(1, model.getLength());

		dt = programDTM.getDataType("/double");
		assertNotNull(dt);
		addAtPoint(dt, 1, 0);
		assertEquals(2, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(1).getLength());
		assertEquals(9, model.getLength());

		DataType dt3 = new Pointer32DataType();
		assertNotNull(dt3);
		addAtPoint(dt3, 2, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(2).isEquivalent(dt3));
		assertEquals(4, model.getComponent(2).getLength());
		assertEquals(13, model.getLength());

		DataType dt4 = programDTM.getDataType("/string");
		assertNotNull(dt4);
		addAtPoint(dt4, 2, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(2) instanceof Pointer);
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt4));
		assertEquals(4, model.getComponent(2).getLength());

		assertNotNull(dt4);
		addAtPoint(dt4, 3, 0);
		dialog = env.waitForDialogComponent(NumberInputDialog.class, 1000);
		assertNotNull(dialog);
		okInput(dialog, 25);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(4, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt4));
		assertEquals(25, model.getComponent(3).getLength());
		assertEquals(38, model.getLength());
	}
}
