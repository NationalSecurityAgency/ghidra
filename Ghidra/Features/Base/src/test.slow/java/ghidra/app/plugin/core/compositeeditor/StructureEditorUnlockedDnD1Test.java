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

public class StructureEditorUnlockedDnD1Test extends AbstractStructureEditorTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	protected void init(Structure dt, Category cat) {
		super.init(dt, cat, false);
	}

	@Test
	public void testDragNDropCancelStringDrop() throws Exception {
		NumberInputDialog dialog = null;
		try {
			init(emptyStructure, pgmRootCat);
			assertEquals(0, model.getNumComponents());

			DataType dt = programDTM.getDataType("/string");
			assertNotNull(dt);
			addAtPoint(dt, 0, 0);
			dialog = waitForDialogComponent(NumberInputDialog.class);
			assertNotNull(dialog);
			cancelInput(dialog);
			dialog = null;

			assertEquals(0, model.getNumComponents());
			assertEquals(0, model.getLength());
			dialog = getDialogComponent(NumberInputDialog.class);
			assertNull(dialog);
		}
		finally {
			if (dialog != null) {
				cancelInput(dialog);
				dialog = null;
			}
		}
	}
}
