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

import java.awt.Window;

import javax.swing.SwingUtilities;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

public class UnionEditorNotifiedTest extends AbstractUnionEditorTest {

	@Override
	protected void init(Union dt, final Category cat, final boolean showInHex) {
		boolean commit = true;
		startTransaction("Union Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dt.clone(dataTypeManager);
			}
			CategoryPath categoryPath = cat.getCategoryPath();
			if (!dt.getCategoryPath().equals(categoryPath)) {
				try {
					dt.setCategoryPath(categoryPath);
				}
				catch (DuplicateNameException e) {
					commit = false;
					Assert.fail(e.getMessage());
				}
			}
		}
		finally {
			endTransaction(commit);
		}
		final Union unionDt = dt;
		runSwing(() -> {
			installProvider(new UnionEditorProvider(plugin, unionDt, showInHex));
			model = provider.getModel();
		});
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		startTransaction("Modify Program");
	}

	@Override
	protected void cleanup() {
		endTransaction(false);
		super.cleanup();
	}

	@Test
	public void testCategoryAdded() {
		// Nothing to test here.
	}

	@Test
	public void testComponentDtCategoryMoved() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals("/aa/bb", getDataType(20).getCategoryPath().getPath());
			pgmTestCat.moveCategory(pgmBbCat, TaskMonitor.DUMMY);
			waitForSwing();
			assertEquals("/testCat/bb", getDataType(20).getCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testEditedDtCategoryMoved() throws Exception {
		try {
			init(simpleUnion, pgmBbCat, false);

			assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
			pgmTestCat.moveCategory(pgmBbCat, TaskMonitor.DUMMY);
			waitForSwing();
			assertTrue(model.getOriginalCategoryPath().getPath().startsWith(
				pgmTestCat.getCategoryPathName()));
			assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDtCategoryRemoved() {
		// Nothing to test here.
	}

	@Test
	public void testEditedDtCategoryRemoved() throws Exception {

		DataTypeManager dtm = complexUnion.getDataTypeManager();
		Union refUnion = (Union) dtm.getDataType("/testCat/refUnion");
		assertNotNull(refUnion);

		Category tempCat;
		try {
			startTransaction("Modify Program");
			tempCat = pgmRootCat.createCategory("Temp");
			tempCat.moveDataType(refUnion, DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		finally {
			endTransaction(true);
		}

		try {
			init(complexUnion, tempCat, false);

			int num = model.getNumComponents();
			// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
			DataType dt18 = getDataType(18).clone(programDTM);
			DataType dt20 = getDataType(20).clone(programDTM);
			SwingUtilities.invokeLater(() -> {
				programDTM.remove(complexUnion, TaskMonitor.DUMMY);
				programDTM.getCategory(pgmRootCat.getCategoryPath()).removeCategory("Temp",
					TaskMonitor.DUMMY);
			});

			waitForSwing();
			// refUnion* gets removed
			assertEquals(num - 1, model.getNumComponents());
			assertTrue(dt18.isEquivalent(getDataType(18)));
			assertTrue(dt20.isEquivalent(getDataType(19)));
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDtCategoryRenamed() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals("/aa/bb", getDataType(20).getCategoryPath().getPath());
			pgmBbCat.setName("NewBB2");// Was /aa/bb
			waitForSwing();
			assertEquals("/aa/NewBB2", getDataType(20).getCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testEditedDtCategoryRenamed() throws Exception {
		try {
			init(simpleUnion, pgmBbCat, false);
			model = provider.getModel();

			assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
			pgmBbCat.setName("NewBB2");// Was /aa/bb
			waitForSwing();
			assertEquals("/aa/NewBB2", model.getOriginalCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testDataTypeAdded() {
		// FUTURE (low priority)
		// Try to add an archive data type to the editor, then add
		// the same named data type to the original data type manager.
	}

	@Test
	public void testComponentDataTypeChanged() {
		try {
			init(complexUnion, pgmTestCat, false);

			// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
			DataType dt12 = getDataType(12).clone(programDTM);// struct array
			DataType dt15 = getDataType(15).clone(programDTM);// struct typedef
			DataType dt20 = getDataType(20).clone(programDTM);// struct
			int len12 = dt12.getLength();
			int len15 = dt15.getLength();
			int len20 = dt20.getLength();
			// Change the struct.  simpleStructure was 29 bytes.
			SwingUtilities.invokeLater(() -> simpleStructure.add(new DWordDataType()));
			waitForSwing();
			// Check that the viewer now has the modified struct.
			// Components 12, 15, & 21 all change size.
			len12 += (3 * 4);
			len15 += 4;
			len20 += 4;
			assertEquals(len12, getDataType(12).getLength());
			assertEquals(len15, getDataType(15).getLength());
			assertEquals(len20, getDataType(20).getLength());
			assertEquals(len12, model.getComponent(12).getLength());
			assertEquals(len15, model.getComponent(15).getLength());
			assertEquals(len20, model.getComponent(20).getLength());
			assertEquals(len12, model.getLength());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testModifiedEditedDataTypeChangedYes() throws Exception {
		Window dialog;
		try {
			init(complexUnion, pgmTestCat, false);

			runSwing(() -> {
				try {
					model.insert(model.getNumComponents(), new ByteDataType(), 1);
					model.insert(model.getNumComponents(), new PointerDataType(), 4);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});

			SwingUtilities.invokeLater(() -> complexUnion.add(new CharDataType()));
			waitForSwing();
			DataType origCopy = complexUnion.clone(null);

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = waitForWindow("Reload Union Editor?");
			assertNotNull(dialog);
			pressButtonByText(dialog, "Yes");
			dialog.dispose();
			dialog = null;

			waitForSwing();
			assertEquals(((Union) origCopy).getNumComponents(), model.getNumComponents());
			assertTrue(origCopy.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			cleanup();
		}
	}

	@Test
	public void testModifiedEditedDataTypeChangedNo() throws Exception {
		Window dialog;
		try {
			init(complexUnion, pgmTestCat, false);

			runSwing(() -> {
				try {
					model.insert(model.getNumComponents(), new ByteDataType(), 1);
					model.insert(model.getNumComponents(), new PointerDataType(), 4);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			DataType viewCopy = model.viewComposite.clone(null);

			SwingUtilities.invokeLater(() -> complexUnion.add(new CharDataType()));
			waitForSwing();

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = waitForWindow("Reload Union Editor?");
			assertNotNull(dialog);
			pressButtonByText(dialog, "No");
			dialog.dispose();
			dialog = null;

			assertEquals(((Union) viewCopy).getNumComponents(), model.getNumComponents());
			assertTrue(viewCopy.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			cleanup();
		}
	}

	@Test
	public void testUnmodifiedEditedDataTypeChanged() {
		try {
			init(complexUnion, pgmTestCat, false);

			SwingUtilities.invokeLater(() -> complexUnion.add(new CharDataType()));
			waitForSwing();
			assertTrue(complexUnion.isEquivalent(model.viewComposite));
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDataTypeMoved() {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals(21, model.getNumComponents());
			assertTrue(simpleStructure.isEquivalent(getDataType(20)));
			assertEquals(simpleStructure.getCategoryPath().getPath(),
				pgmBbCat.getCategoryPath().getPath());
			SwingUtilities.invokeLater(() -> {
				try {
					pgmAaCat.moveDataType(simpleStructure, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					// don't care
				}
			});
			waitForSwing();
			assertEquals(21, model.getNumComponents());
			assertTrue(simpleStructure.isEquivalent(getDataType(20)));
			assertEquals(simpleStructure.getCategoryPath().getPath(),
				pgmAaCat.getCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testEditedDataTypeMoved() {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals(pgmTestCat.getCategoryPathName(),
				model.getOriginalCategoryPath().getPath());
			SwingUtilities.invokeLater(() -> {
				try {
					pgmAaCat.moveDataType(complexUnion, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					// don't care
				}
			});
			waitForSwing();
			assertEquals(pgmAaCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDataTypeRemoved() {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals(21, model.getNumComponents());
			SwingUtilities.invokeLater(() -> complexUnion.getDataTypeManager().remove(
				simpleStructure, TaskMonitor.DUMMY));
			waitForSwing();
			assertEquals(15, model.getNumComponents());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testOnlyComponentDataTypeRemoved() throws Exception {
		try {
			init(emptyUnion, pgmTestCat, false);

			SwingUtilities.invokeLater(() -> {
				try {
					model.add(simpleUnion);
				}
				catch (UsrException e) {
					Assert.fail();
				}
			});
			waitForSwing();
			assertTrue(simpleUnion.isEquivalent(getDataType(0)));

			SwingUtilities.invokeLater(() -> simpleUnion.getDataTypeManager().remove(simpleUnion,
				TaskMonitor.DUMMY));
			waitForSwing();
			assertEquals(0, model.getNumComponents());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testEditedDataTypeRemoved() {
		try {
			init(complexUnion, pgmTestCat, false);

			int num = model.getNumComponents();

			// Clone the data types we want to hold onto for comparison later, since reload can close the viewDTM.
			DataType dt18 = getDataType(18).clone(programDTM);
			DataType dt20 = getDataType(20).clone(programDTM);

			DataTypeManager dtm = complexUnion.getDataTypeManager();
			Union refUnion = (Union) dtm.getDataType("/testCat/refUnion");
			assertNotNull(refUnion);

			SwingUtilities.invokeLater(() -> dtm.remove(refUnion, TaskMonitor.DUMMY)); // remove refUnion
			waitForSwing();

			// refUnion* gets removed (1 component)
			num -= 1;
			assertEquals(num, model.getNumComponents());
			assertTrue(dt18.isEquivalent(getDataType(18)));
			assertTrue(dt20.isEquivalent(getDataType(19)));

			SwingUtilities.invokeLater(
				() -> simpleUnion.getDataTypeManager().remove(simpleUnion, TaskMonitor.DUMMY));
			waitForSwing();

			// All components (3 total) which were dependent upon simpleUnion are removed
			num -= 3;
			assertEquals(num, model.getNumComponents());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDataTypeRenamed() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			assertTrue(simpleUnion.isEquivalent(getDataType(3)));
			assertEquals(simpleUnion.getPathName(), getDataType(3).getPathName());
			SwingUtilities.invokeLater(() -> {
				try {
					simpleUnion.setName("NewSimpleUnion");
				}
				catch (UsrException e) {
					Assert.fail();
				}
			});
			waitForSwing();
			assertTrue(simpleUnion.isEquivalent(getDataType(3)));
			assertEquals(simpleUnion.getPathName(), getDataType(3).getPathName());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testOldNameEditedDataTypeRenamed() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			assertEquals(complexUnion.getDataTypePath(), model.getOriginalDataTypePath());
			assertEquals(complexUnion.getDataTypePath(), model.viewComposite.getDataTypePath());
			SwingUtilities.invokeLater(() -> {
				try {
					complexUnion.setName("NewComplexUnion");
				}
				catch (UsrException e) {
					Assert.fail();
				}
			});
			waitForSwing();
			assertEquals(complexUnion.getDataTypePath(), model.getOriginalDataTypePath());
			assertEquals(complexUnion.getPathName(), model.viewComposite.getPathName());
			assertEquals("NewComplexUnion", model.getCompositeName());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testNewNameEditedDataTypeRenamed() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			SwingUtilities.invokeLater(() -> {
				try {
					model.setName("EditedComplexUnion");
				}
				catch (UsrException e) {
					Assert.fail();
				}
			});
			waitForSwing();
			assertEquals(complexUnion.getDataTypePath(), model.getOriginalDataTypePath());
			assertTrue(!complexUnion.getPathName().equals(model.viewComposite.getPathName()));

			SwingUtilities.invokeLater(() -> {
				try {
					complexUnion.setName("NewComplexUnion");
				}
				catch (UsrException e) {
					Assert.fail();
				}
			});
			waitForSwing();
			assertEquals(complexUnion.getDataTypePath(), model.getOriginalDataTypePath());
			assertTrue(!complexUnion.getPathName().equals(model.viewComposite.getPathName()));
			assertEquals("EditedComplexUnion", model.getCompositeName());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testComponentDataTypeReplaced() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			int numComps = model.getNumComponents();
			assertEquals(87, complexUnion.getComponent(12).getDataType().getLength());
			assertEquals(29, complexUnion.getComponent(15).getDataType().getLength());
			assertEquals(29, complexUnion.getComponent(20).getDataType().getLength());
			assertEquals(87, complexUnion.getComponent(12).getLength());
			assertEquals(29, complexUnion.getComponent(15).getLength());
			assertEquals(29, complexUnion.getComponent(20).getLength());
			assertEquals(87, complexUnion.getLength());
			assertEquals(21, complexUnion.getNumComponents());
			assertEquals(87, getDataType(12).getLength());
			assertEquals(29, getDataType(15).getLength());
			assertEquals(29, getDataType(20).getLength());
			assertEquals(87, model.getComponent(12).getLength());
			assertEquals(29, model.getComponent(15).getLength());
			assertEquals(29, model.getComponent(20).getLength());
			assertEquals(87, model.getLength());

			final Structure newSimpleStructure =
				new StructureDataType(new CategoryPath("/aa/bb"), "simpleStructure", 10);
			newSimpleStructure.add(new PointerDataType(), 8);
			newSimpleStructure.replace(2, new CharDataType(), 1);

			// Change the struct.  simpleStructure was 29 bytes.
			programDTM.replaceDataType(simpleStructure, newSimpleStructure, true);
			waitForSwing();

			// Check that the viewer now has the modified struct.
			// Components 12, 15, & 21 all change size.
			assertEquals(54, complexUnion.getComponent(12).getDataType().getLength());
			assertEquals(18, complexUnion.getComponent(15).getDataType().getLength());
			assertEquals(18, complexUnion.getComponent(20).getDataType().getLength());
			assertEquals(54, complexUnion.getComponent(12).getLength());
			assertEquals(18, complexUnion.getComponent(15).getLength());
			assertEquals(18, complexUnion.getComponent(20).getLength());
			assertEquals(54, getDataType(12).getLength());
			assertEquals(18, getDataType(15).getLength());
			assertEquals(18, getDataType(20).getLength());
			assertEquals(54, model.getComponent(12).getLength());
			assertEquals(18, model.getComponent(15).getLength());
			assertEquals(18, model.getComponent(20).getLength());
			assertEquals(56, model.getLength());
			assertEquals(numComps, model.getNumComponents());
		}
		finally {
			cleanup();
		}
	}

	@Test
	public void testModifiedEditedDataTypeReplacedYes() throws Exception {
		Window dialog;
		try {
			init(complexUnion, pgmTestCat, false);

			runSwing(() -> {
				try {
					model.insert(model.getNumComponents(), new ByteDataType(), 1);
					model.insert(model.getNumComponents(), new PointerDataType(), 4);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});

			final Union newComplexUnion =
				new UnionDataType(pgmTestCat.getCategoryPath(), complexUnion.getName());
			newComplexUnion.add(new PointerDataType(), 8);
			newComplexUnion.add(new CharDataType(), 1);

			programDTM.replaceDataType(complexUnion, newComplexUnion, true);
			waitForSwing();
			DataType origCopy = newComplexUnion.clone(null);

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = env.waitForWindow("Reload Union Editor?", 1000);
			assertNotNull(dialog);
			pressButtonByText(dialog, "Yes");
			dialog.dispose();
			dialog = null;

			assertEquals(((Union) origCopy).getNumComponents(), model.getNumComponents());
			assertTrue(origCopy.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			cleanup();
		}
	}

	@Test
	public void testModifiedEditedDataTypeReplacedNo() throws Exception {
		Window dialog;
		try {
			init(complexUnion, pgmTestCat, false);

			runSwing(() -> {
				try {
					model.insert(model.getNumComponents(), new ByteDataType(), 1);
					model.insert(model.getNumComponents(), new PointerDataType(), 4);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			DataType viewCopy = model.viewComposite.clone(null);

			final Union newComplexUnion =
				new UnionDataType(pgmTestCat.getCategoryPath(), complexUnion.getName());
			newComplexUnion.add(new PointerDataType(), 8);
			newComplexUnion.add(new CharDataType(), 1);

			programDTM.replaceDataType(complexUnion, newComplexUnion, true);
			waitForSwing();

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = env.waitForWindow("Reload Union Editor?", 1000);
			assertNotNull(dialog);
			pressButtonByText(dialog, "No");
			dialog.dispose();
			dialog = null;

			assertEquals(((Union) viewCopy).getNumComponents(), model.getNumComponents());
			assertTrue(viewCopy.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			cleanup();
		}
	}

	@Test
	public void testUnModifiedEditedDataTypeReplaced() throws Exception {
		try {
			init(complexUnion, pgmTestCat, false);

			Union newComplexUnion =
				new UnionDataType(pgmTestCat.getCategoryPath(), complexUnion.getName());
			newComplexUnion.add(new PointerDataType(), 8);
			newComplexUnion.add(new CharDataType(), 1);

			assertTrue(complexUnion.isEquivalent(model.viewComposite));
			programDTM.replaceDataType(complexUnion, newComplexUnion, true);
			waitForSwing();
			assertTrue(newComplexUnion.isEquivalent(model.viewComposite));
		}
		finally {
			cleanup();
		}
	}

}
