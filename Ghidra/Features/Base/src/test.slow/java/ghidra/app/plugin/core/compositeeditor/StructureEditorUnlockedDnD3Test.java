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

public class StructureEditorUnlockedDnD3Test extends AbstractStructureEditorTest {

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
	public void testDragNDropInsertDifferentTypes() throws Exception {
		NumberInputDialog dialog = null;
		init(emptyStructure, pgmRootCat);
		DataType dt;

		assertEquals(0, model.getNumComponents());
		assertEquals(0, model.getLength());

		dt = programDTM.getDataType("/byte");
		assertNotNull(dt);
		insertAtPoint(dt, 0, 0);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(1, model.getLength());

		dt = programDTM.getDataType("/double");
		assertNotNull(dt);
		insertAtPoint(dt, 0, 0);
		assertEquals(2, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(dt.getLength(), model.getComponent(0).getLength());
		assertEquals(9, model.getLength());

		DataType dt3 = programDTM.getDataType("/undefined *32");
		assertNotNull(dt3);
		insertAtPoint(dt3, 1, 0);
		assertEquals(3, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(dt3));
		assertEquals(4, model.getComponent(1).getLength());
		assertEquals(13, model.getLength());

		DataType dt4 = programDTM.getDataType("/string");
		assertNotNull(dt4);

		assertNotNull(dt4);
		insertAtPoint(dt4, 0, 0);
		dialog = env.waitForDialogComponent(NumberInputDialog.class, 1000);
		assertNotNull(dialog);
		okInput(dialog, 25);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(4, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt4));
		assertEquals(25, model.getComponent(0).getLength());
		assertEquals(38, model.getLength());
	}
}
