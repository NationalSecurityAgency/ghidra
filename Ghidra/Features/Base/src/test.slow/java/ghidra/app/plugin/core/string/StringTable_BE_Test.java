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
package ghidra.app.plugin.core.string;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramSelection;
import ghidra.program.util.string.FoundString;
import ghidra.test.*;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.field.*;

/**
 *
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class StringTable_BE_Test extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private StringTablePlugin plugin;
	private DockingActionIf searchAction;
	private CodeBrowserPlugin cbPlugin;

	public StringTable_BE_Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(StringTablePlugin.class.getName());
		plugin = env.getPlugin(StringTablePlugin.class);
		openProgram();

		searchAction = getAction(plugin, "Search for Strings");
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);
		env.showTool();
	}

	private void openProgram() throws Exception {
		// make big endian program
		ToyProgramBuilder builder = new ToyProgramBuilder("TestGhidraSearches", true);
		builder.createMemory("test", "0x0", 1000);

		// create bytes for string at 100
		builder.setBytes("0x100", "61, 62, 63, 64, 65, 66, 67, 68");

		// create defined string at 200
		builder.createEncodedString("200", "abcdefghij", StandardCharsets.US_ASCII, false);

		// create conflict at 300
		builder.setBytes("0x300", "61, 62, 63, 64, 65, 66, 67");
		builder.applyDataType("0x300", new PointerDataType());
		builder.applyDataType("0x304", new PointerDataType());

		// create a unicode
		builder.setBytes("0x400", "00, 61, 00, 62, 00, 63, 00, 64, 00, 65, 00, 66, 00");
		program = builder.getProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	private Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testSearchSelection() throws Exception {
		final AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x1000));

		// select the address set
		cbPlugin.firePluginEvent(new ProgramSelectionPluginEvent(cbPlugin.getName(),
			new ProgramSelection(set), program));

		SearchStringDialog dialog = getDialog();

		// turn off null Terminate box
		JCheckBox cb = (JCheckBox) findButton(dialog.getComponent(), "Require Null Termination");
		cb.setSelected(false);

		pressButtonByText(dialog.getComponent(), "Search");

		@SuppressWarnings("unchecked")
		StringTableProvider provider =
			((List<StringTableProvider>) getInstanceField("transientProviders", plugin)).get(0);
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		GhidraTable table = (GhidraTable) getInstanceField("table", provider);
		waitForTableModel(model);

		setAutoLabelCheckbox(provider, true);

		// test the results size
		assertEquals(4, model.getRowCount());

		// test the first and last ones
		assertEquals(addr(0x100), addressCell(model, 0));
		assertEquals(addr(0x400), addressCell(model, 3));

		// ********************** test Make Unicode String
		// select row for address 400
		Address address = addr(0x400);
		selectRows(table, address);

		// make string
		DockingAction makeStringAction =
			(DockingAction) getInstanceField("makeStringAction", provider);
		performAction(makeStringAction, true);
		waitForTableModel(model);

		// test that the string was actually made correctly
		// test that the string was actually made correctly
		Data d = program.getListing().getDataAt(addr(0x400));
		assertEquals(12, d.getLength());

		String str = (String) d.getValue();
		assertEquals("abcdef", str);

		DataType dt = d.getBaseDataType();
		assertEquals("unicode", dt.getName());

		// test that the label was made correctly
		Symbol sym = program.getSymbolTable().getPrimarySymbol(addr(0x400));
		assertEquals("u_abcdef", sym.getName());

		selectRows(table, address);
		int selectedRow = table.getSelectedRow();

		// test that the table was updated with the label and preview
		assertEquals("u_abcdef", labelCell(model, selectedRow));

		CodeUnitTableCellData value = previewCell(model, selectedRow);
		assertEquals("unicode u\"abcdef\"", value.getDisplayString());

	}

	private Address addressCell(StringTableModel model, int row) {
		int addressColumnIndex = model.getColumnIndex(AddressTableColumn.class);
		AddressBasedLocation location =
			(AddressBasedLocation) getValue(model, row, addressColumnIndex);
		return location.getAddress();
	}

	private String labelCell(StringTableModel model, int row) {
		int labelColumnIndex = model.getColumnIndex(LabelTableColumn.class);
		return (String) getValue(model, row, labelColumnIndex);
	}

	private CodeUnitTableCellData previewCell(StringTableModel model, int row) {
		int previewColumnIndex = model.getColumnIndex(CodeUnitTableColumn.class);
		return (CodeUnitTableCellData) getValue(model, row, previewColumnIndex);
	}

	private Object getValue(final StringTableModel model, final int row, final int column) {
		final AtomicReference<Object> reference = new AtomicReference<>();

		runSwing(() -> {
			FoundString foundString = model.getRowObject(row);
			reference.set(model.getColumnValueForRow(foundString, column));
		});
		return reference.get();
	}

	@Test
	public void testSearchAlligned() throws Exception {

		// set up address set to select to the .data section
		final AddressSet set = new AddressSet();
		set.addRange(addr(0x100), addr(0x1000));

		waitForPostedSwingRunnables();

		// select the address set
		cbPlugin.firePluginEvent(new ProgramSelectionPluginEvent(cbPlugin.getName(),
			new ProgramSelection(set), program));

		SearchStringDialog dialog = getDialog();

		// turn off null Terminate box
		JCheckBox cb = (JCheckBox) findButton(dialog.getComponent(), "Require Null Termination");
		cb.setSelected(false);
		setAlignmentFieldValue(dialog, 4);
		pressButtonByText(dialog.getComponent(), "Search");

		@SuppressWarnings("unchecked")
		StringTableProvider provider =
			((List<StringTableProvider>) getInstanceField("transientProviders", plugin)).get(0);
		StringTableModel model = (StringTableModel) getInstanceField("stringModel", provider);
		waitForTableModel(model);

		// test the results size
		assertEquals(4, model.getRowCount());

		// test the first and last ones
		assertEquals(addr(0x100), addressCell(model, 0));
		assertEquals(addr(0x400), addressCell(model, 3));
	}

	private void setAutoLabelCheckbox(final StringTableProvider provider, final boolean b) {
		runSwing(() -> {
			JCheckBox autoLabelCB = (JCheckBox) getInstanceField("autoLabelCheckbox", provider);
			autoLabelCB.setSelected(b);
		});
	}

	private void setAlignmentFieldValue(final SearchStringDialog dialog, final int alignment) {
		runSwing(() -> {
			IntegerTextField alignmentField =
				(IntegerTextField) getInstanceField("alignField", dialog);
			alignmentField.setValue(alignment);
		});
	}

	private void selectRows(GhidraTable table, Address... addrs) {
		table.clearSelection();
		for (Address address : addrs) {
			int row = findRow((StringTableModel) table.getModel(), address);
			table.addRowSelectionInterval(row, row);
		}

	}

	private int findRow(StringTableModel model, Address address) {
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {
			FoundString string = model.getRowObject(i);
			if (string.getAddress().equals(address)) {
				return i;
			}
		}
		return -1;
	}

	private AbstractButton findButton(Container container, String text) {
		Component[] comp = container.getComponents();
		for (Component element : comp) {
			if ((element instanceof AbstractButton) &&
				((AbstractButton) element).getText().equals(text)) {
				return (AbstractButton) element;
			}
			else if (element instanceof Container) {
				AbstractButton b = findButton((Container) element, text);
				if (b != null) {
					return b;
				}
			}
		}
		return null;
	}

	private SearchStringDialog getDialog() throws Exception {
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);
		CodeViewerProvider cbProvider = cb.getProvider();
		SwingUtilities.invokeLater(
			() -> searchAction.actionPerformed(cbProvider.getActionContext(null)));
		waitForPostedSwingRunnables();
		return getDialogComponent(SearchStringDialog.class);
	}
}
