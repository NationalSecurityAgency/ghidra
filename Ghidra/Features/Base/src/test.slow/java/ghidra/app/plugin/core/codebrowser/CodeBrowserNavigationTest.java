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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

import org.junit.Test;

import docking.widgets.table.GTable;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.framework.options.Options;
import ghidra.program.util.*;
import ghidra.util.table.GhidraProgramTableModel;

public class CodeBrowserNavigationTest extends AbstractCodeBrowserNavigationTest {

	@Test
	public void testOperandNavigation() throws Exception {

		cb.goTo(new OperandFieldLocation(program, addr("1002000"), null, null, null, 0, 0));
		assertEquals(addr("1002000"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1003000"), cb.getCurrentAddress());

		cb.goTo(new OperandFieldLocation(program, addr("1004000"), null, null, null, 0, 0));
		assertEquals(addr("1004000"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1004010"), cb.getCurrentAddress());

		// verify case where there exists both an inferred variable reference and an extended memory reference on an operand (i.e., => )

		cb.goTo(new OperandFieldLocation(program, addr("1006004"), (int[]) null, null,
			"[foo]=>DAT_01005012", 1, 0, 3));
		assertEquals(addr("1006004"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1006000"), cb.getCurrentAddress());
		ProgramLocation currentLocation = cb.getCurrentLocation();
		assertTrue(currentLocation instanceof VariableNameFieldLocation);
		assertEquals("foo", ((VariableNameFieldLocation) currentLocation).getName());

		cb.goTo(new OperandFieldLocation(program, addr("1006004"), (int[]) null, null,
			"[foo]=>DAT_01005012", 1, 0, 9));
		assertEquals(addr("1006004"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1005012"), cb.getCurrentAddress());
		currentLocation = cb.getCurrentLocation();
		assertTrue(currentLocation instanceof LabelFieldLocation);
		assertEquals("DAT_01005012", ((LabelFieldLocation) currentLocation).getName());
	}

	@Test
	public void testXrefNaviagation() throws Exception {

		goTo(new XRefFieldLocation(program, addr("1004010"), null, addr("1004000"), 0, 2));
		assertEquals(addr("1004010"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1004000"), cb.getCurrentAddress());

		goTo(new XRefFieldLocation(program, addr("1004010"), null, addr("1004030"), 1, 4));
		assertEquals(addr("1004010"), cb.getCurrentAddress());
		assertTrue(isPreviousInHistoryEnabled());

		clearHistory();
		assertFalse(isPreviousInHistoryEnabled());

		click(cb, 2);
		assertEquals(addr("1004030"), cb.getCurrentAddress());

		assertTrue(isPreviousInHistoryEnabled());
	}

	@Test
	public void testFunctionNaviagation() throws Exception {

		cb.goTo(new ProgramLocation(program, addr("1006300")));
		assertEquals(addr("1006300"), cb.getCurrentAddress());

		prevFunction();
		assertEquals(addr("1006200"), cb.getCurrentAddress());

		prevFunction();
		assertEquals(addr("1006100"), cb.getCurrentAddress());

		prevFunction();
		assertEquals(addr("1006000"), cb.getCurrentAddress());

		nextFunction();
		assertEquals(addr("1006100"), cb.getCurrentAddress());

		nextFunction();
		assertEquals(addr("1006200"), cb.getCurrentAddress());

		// last function, so stay
		nextFunction();
		assertEquals(addr("1006200"), cb.getCurrentAddress());
	}

	@Test
	public void testXrefNaviagationMoreField() throws Exception {

		Options opt = getTool().getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		opt.setInt("XREFs Field" + Options.DELIMITER + "Maximum Number of XREFs to Display", 2);

		cb.goTo(new XRefFieldLocation(program, addr("1004010"), null, addr("1004030"), 2, 2));
		assertEquals(addr("1004010"), cb.getCurrentAddress());

		click(cb, 2);

		TableComponentProvider<?>[] providers = getProviders();
		assertEquals(1, providers.length);
		GhidraProgramTableModel<?> model = providers[0].getModel();
		waitForTableModel(model);
		assertEquals(3, model.getRowCount());

		runSwing(() -> providers[0].closeComponent());
	}

	@Test
	public void testMultipleRefs() throws Exception {

		cb.goTo(new OperandFieldLocation(program, addr("1004050"), null, null, null, 0, 0));
		assertEquals(addr("1004050"), cb.getCurrentAddress());

		click(cb, 2);

		GTable table = waitForResults();

		TableColumnModel columnModel = table.getColumnModel();
		int columnIndex = columnModel.getColumnIndex("Location");
		TableModel model = table.getModel();

		assertEquals("01008010", model.getValueAt(0, columnIndex).toString());
		assertEquals("01008020", model.getValueAt(1, columnIndex).toString());
		assertEquals("01008030", model.getValueAt(2, columnIndex).toString());
		assertEquals("01008040", model.getValueAt(3, columnIndex).toString());
		assertEquals("01008050", model.getValueAt(4, columnIndex).toString());
		assertEquals("01008060", model.getValueAt(5, columnIndex).toString());
		assertEquals("01008070", model.getValueAt(6, columnIndex).toString());
		assertEquals("01008080", model.getValueAt(7, columnIndex).toString());
		assertEquals("01008090", model.getValueAt(8, columnIndex).toString());

		getProviders()[0].closeComponent();
	}

	@Test
	public void testBadAddress() throws Exception {

		cb.goTo(new OperandFieldLocation(program, addr("1002010"), null, null, null, 0, 0));
		assertEquals(addr("1002010"), cb.getCurrentAddress());

		click(cb, 2);
		assertEquals(addr("1002010"), cb.getCurrentAddress());
	}

}
