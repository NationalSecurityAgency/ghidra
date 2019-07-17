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
package ghidra.app.plugin.core.register;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.widgets.OptionDialog;
import docking.widgets.table.*;
import ghidra.app.cmd.register.SetRegisterCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.services.*;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.*;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.ProgramTableModel;

class RegisterValuesPanel extends JPanel {
	private static final String VALUE_COLUMN_NAME = "Value";
	private static final String START_ADDRESS_COLUMN_NAME = "Start Address";
	private static final String END_ADDRESS_COLUMN_NAME = "End Address";
	private static final Color REGISTER_MARKER_COLOR = new Color(0, 153, 153);

	private Program currentProgram;
	private GhidraTable table;
	private Register selectedRegister;
	private PluginTool tool;
	private MarkerSet markerSet;
	private boolean includeDefaultValues;
	private RegisterValuesTableModel model;
	private AddressSet markerAddressSet;
	private boolean isShowing;
	private final RegisterManagerProvider provider;

	RegisterValuesPanel(PluginTool tool, RegisterManagerProvider provider) {
		this.tool = tool;
		this.provider = provider;
		setLayout(new BorderLayout());
		table = createBasicTable();
		add(new JScrollPane(table), BorderLayout.CENTER);
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int row = table.rowAtPoint(e.getPoint());
				int col = table.columnAtPoint(e.getPoint());
				col = table.convertColumnIndexToModel(col);
				if (e.getClickCount() == 2 && row >= 0) {
					editRow(row);
				}
			}
		});
		table.setDefaultRenderer(RegisterValueRange.class, new RegisterValueRenderer(table));

	}

	private void editRow(int row) {
		RegisterValueRange range = model.values.get(row);
		Address start = range.getStartAddress();
		Address end = range.getEndAddress();
		BigInteger value = range.getValue();
		EditRegisterValueDialog dialog = new EditRegisterValueDialog(selectedRegister, start, end,
			value, currentProgram.getAddressFactory());
		tool.showDialog(dialog, this);

		if (!dialog.wasCancelled()) {
			Address newStart = dialog.getStartAddress();
			Address newEnd = dialog.getEndAddress();
			BigInteger newValue = dialog.getValue();
			updateValue(start, end, newStart, newEnd, newValue);
		}
	}

	private void updateValue(Address start, Address end, Address newStart, Address newEnd,
			BigInteger newValue) {
		CompoundCmd cmd = new CompoundCmd("Update Register Range");
		Command cmd1 = new SetRegisterCmd(selectedRegister, start, end, null);
		Command cmd2 = new SetRegisterCmd(selectedRegister, newStart, newEnd, newValue);
		cmd.add(cmd1);
		cmd.add(cmd2);
		tool.execute(cmd, currentProgram);

	}

	private GhidraTable createBasicTable() {
		// default model with no cell editing
		model = new RegisterValuesTableModel();
		table = new GhidraTable(model);

		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setRowSelectionAllowed(true);
		table.setColumnSelectionAllowed(false);
		GoToService goToService = tool.getService(GoToService.class);
		table.installNavigation(goToService, goToService.getDefaultNavigatable());
		table.setNavigateOnSelectionEnabled(true);
		return table;
	}

	GhidraTable getTable() {
		return table;
	}

	void setProgram(Program program) {
		clearMarkers(this.currentProgram); // clear the markers before we set the new program
		this.currentProgram = program;
		setRegister(null);
	}

	void setRegister(Register register) {
		this.selectedRegister = register;
		if (!isShowing) {
			return;
		}
		try {
			AddressSet set = new AddressSet(); // create an address set for the markers
			List<RegisterValueRange> data = new ArrayList<>();
			if (register != null) {
				ProgramContext context = currentProgram.getProgramContext();
				AddressRangeIterator registerValueAddressRanges =
					context.getRegisterValueAddressRanges(register);

				// If we are including default values, get an iterator over the defaults and combine it
				// with the set values.
				if (includeDefaultValues) {
					AddressRangeIterator defaultIt =
						context.getDefaultRegisterValueAddressRanges(register);
					registerValueAddressRanges =
						new CombinedAddressRangeIterator(registerValueAddressRanges, defaultIt);
				}

				try {
					RegisterValueRange lastValueRange = null;
					while (registerValueAddressRanges.hasNext()) {
						AddressRange range = registerValueAddressRanges.next();
						BigInteger value = context.getValue(register, range.getMinAddress(), false);
						if (value == null) {
							continue;
						}
						boolean isDefault = checkIsDefaultValue(register, context, range, value);
						if (lastValueRange != null && lastValueRange.getValue().equals(value) &&
							isNextAddress(lastValueRange.getEndAddress(), range.getMinAddress())) {
							lastValueRange.setEndAddress(range.getMaxAddress());
						}
						else {
							lastValueRange = new RegisterValueRange(range, value, isDefault);
							data.add(lastValueRange);
						}
						if (!isDefault) {
							set.add(range);
						}
					}
				}
				catch (ConcurrentModificationException e) {
					// just break out of loop;
				}
			}
			model.setValues(data);
			markerAddressSet = set;
			updateMarkers();
		}
		catch (ConcurrentModificationException e) {
			provider.scheduleUpdate();
		}
	}

	private boolean isNextAddress(Address addr1, Address addr2) {
		if (addr1.getAddressSpace() != addr2.getAddressSpace()) {
			return false;
		}
		return addr1.next().equals(addr2);
	}

	private boolean checkIsDefaultValue(Register register, ProgramContext context,
			AddressRange range, BigInteger value) {
		if (!includeDefaultValues) {
			return false; // we have no default values to check
		}

		RegisterValue defaultRegsiterValue =
			context.getDefaultValue(register, range.getMinAddress());
		if (defaultRegsiterValue != null && defaultRegsiterValue.hasValue()) {
			BigInteger defaultValue = defaultRegsiterValue.getUnsignedValue();
			if (value.equals(defaultValue)) {
				return true;
			}
		}
		return false;
	}

	void updateMarkers() {
		MarkerService service = tool.getService(MarkerService.class);
		if (service == null) {
			return;
		}

		if (currentProgram == null) {
			return;
		}

		if (markerSet == null) {
			markerSet = service.createAreaMarker("Register Values",
				"Area where selected register has defined values", currentProgram, 0, true, true,
				false, REGISTER_MARKER_COLOR);
		}

		markerSet.clearAll();
		markerSet.add(markerAddressSet);
	}

	private void clearMarkers(Program program) {
		if (markerSet == null || program == null) {
			return;
		}

		MarkerService service = tool.getService(MarkerService.class);
		if (service == null) {
			return;
		}

		service.removeMarker(markerSet, program);
		markerSet = null;
	}

	void deleteSelectedRanges() {
		CompoundCmd cmd = new CompoundCmd("Delete Register Value Ranges");
		int[] rows = table.getSelectedRows();
		boolean containsDefaultValues = false;
		for (int row : rows) {
			RegisterValueRange rvr = model.values.get(row);
			if (rvr.isDefault()) {
				containsDefaultValues = true;
			}
			cmd.add(new SetRegisterCmd(selectedRegister, rvr.getStartAddress(), rvr.getEndAddress(),
				null));
		}
		if (containsDefaultValues) {
			int result = OptionDialog.showOptionDialog(table, "Warning",
				"The selected ranges " +
					"contain default values that can't be deleted.\n  Do you want to continue?",
				"Yes", OptionDialog.WARNING_MESSAGE);
			if (result == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}
		if (cmd.size() > 0) {
			tool.execute(cmd, currentProgram);
		}
	}

	void selectedRanges() {
		int[] rows = table.getSelectedRows();
		AddressSet set = new AddressSet();
		for (int element : rows) {
			Address start = (Address) model.getValueAt(element, 0);
			Address end = (Address) model.getValueAt(element, 1);
			set.addRange(start, end);
		}
		ProgramSelection selection = new ProgramSelection(set);
		tool.firePluginEvent(
			new ProgramSelectionPluginEvent("Registers", selection, currentProgram));
	}

	private class RegisterValuesTableModel extends AbstractSortedTableModel<RegisterValueRange>
			implements ProgramTableModel {
		List<RegisterValueRange> values;

		RegisterValuesTableModel() {
			this.values = new ArrayList<>();
		}

		void setValues(List<RegisterValueRange> values) {
			this.values = values;
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return "Register Values";
		}

		@Override
		public int getColumnCount() {
			return 3;
		}

		@Override
		public int getRowCount() {
			return values.size();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			switch (columnIndex) {
				case 0:
				case 1:
					return Address.class;
				default:
					return RegisterValueRange.class;
			}

		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public String getColumnName(int column) {
			switch (column) {
				case 0:
					return START_ADDRESS_COLUMN_NAME;
				case 1:
					return END_ADDRESS_COLUMN_NAME;
				default:
					return VALUE_COLUMN_NAME;
			}
		}

		@Override
		public Program getProgram() {
			return currentProgram;
		}

		@Override
		public ProgramLocation getProgramLocation(int row, int column) {
			RegisterValueRange range = values.get(row);
			switch (column) {
				case 0:
					return new ProgramLocation(currentProgram, range.getStartAddress());
				case 1:
					return new ProgramLocation(currentProgram, range.getEndAddress());
				default:
					return null;
			}
		}

		@Override
		public ProgramSelection getProgramSelection(int[] rows) {
			return null;
		}

		@Override
		public Object getColumnValueForRow(RegisterValueRange range, int columnIndex) {
			switch (columnIndex) {
				case 0:
					return range.getStartAddress();
				case 1:
					return range.getEndAddress();
				default:
					return range;
			}
		}

		@Override
		public List<RegisterValueRange> getModelData() {
			return values;
		}

		@Override
		protected Comparator<RegisterValueRange> createSortComparator(int columnIndex) {
			return new RegisterValueRangeComparator(columnIndex);
		}

	}

	void setShowDefaultValues(boolean b) {
		includeDefaultValues = b;
		setRegister(selectedRegister);
	}

	void setAddress(Address address) {
		int numRows = model.getRowCount();
		for (int i = 0; i < numRows; i++) {
			Address start = (Address) model.getValueAt(i, 0);
			Address end = (Address) model.getValueAt(i, 1);
			if (start.compareTo(address) <= 0 && end.compareTo(address) >= 0) {
				table.changeSelection(i, 0, false, false);
				return;
			}
		}
		table.clearSelection();
	}

	void setIsShowing(boolean b) {
		isShowing = b;
		if (isShowing) {
			setRegister(selectedRegister);
		}
		else {
			markerAddressSet = new AddressSet();
			updateMarkers();
		}
	}

	void dispose() {
		table.dispose();
	}
}

class RegisterValueRangeComparator implements Comparator<RegisterValueRange> {

	private final int sortColumn;

	public RegisterValueRangeComparator(int sortColumn) {
		this.sortColumn = sortColumn;
	}

	@Override
	public int compare(RegisterValueRange range1, RegisterValueRange range2) {
		switch (sortColumn) {
			case 0:
				return range1.getStartAddress().compareTo(range2.getStartAddress());
			case 1:
				return range1.getStartAddress().compareTo(range2.getStartAddress());
			case 2:
				return range1.getValue().compareTo(range2.getValue());
		}
		return 0;
	}

}

class RegisterValueRange {
	private BigInteger value;
	private boolean isDefault;
	private Address start;
	private Address end;

	public RegisterValueRange(AddressRange range, BigInteger value, boolean isDefault) {
		this.value = value;
		this.isDefault = isDefault;
		this.start = range.getMinAddress();
		this.end = range.getMaxAddress();
	}

	public void setEndAddress(Address maxAddress) {
		end = maxAddress;
	}

	public BigInteger getValue() {
		return value;
	}

	public Address getEndAddress() {
		return end;
	}

	public Address getStartAddress() {
		return start;
	}

	public boolean isDefault() {
		return isDefault;
	}

	@Override
	public String toString() {
		if (value == null) {
			return "";
		}
		return "0x" + value.toString(16) + (isDefault ? "  (default)" : "");
	}
}

class RegisterValueRenderer extends GTableCellRenderer {

	private Color defaultColor = Color.LIGHT_GRAY;

	RegisterValueRenderer(JTable table) {
		setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0));
		setFont(new Font("monospaced", Font.PLAIN, 12));
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label = (JLabel) super.getTableCellRendererComponent(data);

		Object value = data.getValue();

		RegisterValueRange cvalue = (RegisterValueRange) value;

		if (cvalue.isDefault()) {
			label.setForeground(defaultColor);
		}

		return label;
	}
}
