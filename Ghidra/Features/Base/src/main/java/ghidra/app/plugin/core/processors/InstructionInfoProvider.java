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
package ghidra.app.plugin.core.processors;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import docking.action.ToggleDockingAction;
import docking.action.builder.ToggleActionBuilder;
import generic.theme.Gui;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.util.InstructionUtils;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import resources.Icons;

/**
 * Component provider to show the instruction info.
 *
 */
class InstructionInfoProvider extends ComponentProviderAdapter implements DomainObjectListener {
	private static final String FONT_ID = "font.plugin.instruction.info";
	private JPanel mainPanel;
	private JSplitPane pane;
	private ShowInstructionInfoPlugin plugin;
	private Program program;

	private JTextArea instructionText;
	private JTable opTable;

	private ToggleDockingAction dynamicUpdateAction;

	private OperandModel operandModel;
	private Address myAddr;

	InstructionInfoProvider(ShowInstructionInfoPlugin plugin, boolean isDynamic) {
		super(plugin.getTool(), "Instruction Info", plugin.getName());
		this.plugin = plugin;

		buildMainPanel();
		setTransient();
		setWindowMenuGroup("Instruction Info");
		addToTool();
		createActions(isDynamic);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "Show_Instruction_Info_Window");
	}

	private void createActions(boolean isDynamic) {
		dynamicUpdateAction = new ToggleActionBuilder("Dynamic Update", plugin.getName())
				.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
				.description("Update this panel with navigation")
				.onAction(ctx -> dynamicStateChanged())
				.selected(isDynamic)
				.buildAndInstallLocal(this);
		dynamicStateChanged();
	}

	boolean dynamicUpdateSelected() {
		return dynamicUpdateAction.isSelected();
	}

	/**
	 * Set the status text on this dialog.
	 */
	void setStatusText(String msg) {
		tool.setStatusInfo(msg);
	}

	void dispose() {
		setProgram(null);
		removeFromTool();
		plugin = null;
		tool = null;
	}

	@Override
	public void componentHidden() {
		setProgram(null);
	}

	/**
	 * Define the Main panel.
	 *
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel() {

		mainPanel = new JPanel(new BorderLayout());

		instructionText = new JTextArea();
		Gui.registerFont(instructionText, FONT_ID);
		instructionText.setEditable(false);

		operandModel = new OperandModel();
		opTable = new GhidraTable(operandModel);
		Gui.registerFont(opTable, FONT_ID);
		opTable.setPreferredScrollableViewportSize(new Dimension(425, 105));
		//opTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

		pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(instructionText),
			new JScrollPane(opTable));
		pane.setResizeWeight(.25);
		mainPanel.add(pane, BorderLayout.CENTER);

		mainPanel.validate();

		return mainPanel;
	}

	protected void dynamicStateChanged() {
		plugin.dynamicStateChanged(this, dynamicUpdateSelected());
	}

	void setAddress(Address address) {
		if (program == null) {
			return;
		}

		Instruction instruction = getInstruction(address);
		myAddr = instruction != null ? instruction.getMinAddress() : address;
		SleighDebugLogger debug = null;
		if (instruction != null) {
			debug =
				new SleighDebugLogger(instruction.getProgram(), myAddr, SleighDebugMode.MASKS_ONLY);
		}
		updateTitle(instruction);
		updateInstructionText(instruction, debug);
		operandModel.setInstruction(instruction, debug);
	}

	public Instruction getInstruction() {
		return operandModel.instruction;
	}

	private Instruction getInstruction(Address address) {
		if (address == null) {
			return null;
		}
		return program.getListing().getInstructionContaining(address);
	}

	private void updateTitle(Instruction instruction) {
		String title =
			(myAddr != null && instruction != null) ? getName() + ": Address " + myAddr : getName();
		setTitle(title);
	}

	void setProgram(Program program) {

		operandModel.setInstruction(null, null);

		if (this.program != null) {
			this.program.removeListener(this);
		}

		this.program = program;

		if (this.program != null) {
			this.program.addListener(this);
		}
		setSubTitle(program == null ? "" : "(" + program.getDomainFile().getName() + ")");
	}

	void show() {
		pane.setDividerLocation(1.0 / 5.0);
		setVisible(true);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		setAddress(myAddr);
	}

	public void setDynamic(boolean dynamic) {
		dynamicUpdateAction.setSelected(dynamic);
		dynamicStateChanged();
	}

	public Program getProgram() {
		return program;
	}

	private void updateInstructionText(Instruction instruction, SleighDebugLogger debug) {
		if (instruction == null) {
			instructionText.setText("-- No Instruction --");
			return;
		}
		String details = InstructionUtils.getFormattedInstructionDetails(instruction, debug);
		instructionText.setText(details);
		instructionText.setCaretPosition(0);
	}

	class OperandModel extends DefaultTableModel {

		private Instruction instruction;
		private SleighDebugLogger debug;

		public void setInstruction(Instruction instruction, SleighDebugLogger debug) {
			this.instruction = instruction;
			this.debug = debug;
			this.fireTableChanged(null);
		}

		/**
		 * Returns the number of columns in this data table.
		 * 
		 * @return the number of columns in the model
		 */
		@Override
		public int getColumnCount() {
			return instruction != null ? instruction.getNumOperands() + 1 : 0;
		}

		/**
		 * Returns the column name.
		 * 
		 * @return a name for this column using the string value of the appropriate member in
		 *         <I>columnIdentfiers</I>. If <I>columnIdentfiers</I> is null or does not have and
		 *         entry for this index return the default name provided by the superclass.
		 */
		@Override
		public String getColumnName(int column) {
			if (column == 0) {
				return "";
			}
			return "Operand-" + (column - 1);
		}

		/**
		 * Returns the number of rows in this data table.
		 * 
		 * @return the number of rows in the model
		 */
		@Override
		public int getRowCount() {
			return 9;
		}

		/**
		 * Returns an attribute value for the cell at <I>row</I> and <I>column</I>.
		 *
		 * @param row the row whose value is to be looked up
		 * @param column the column whose value is to be looked up
		 * @return the value Object at the specified cell
		 * @exception ArrayIndexOutOfBoundsException if an invalid row or column was given.
		 */
		@Override
		public Object getValueAt(int row, int column) {
			if (instruction == null) {
				return null;
			}
			if (column == 0) {
				return switch (row) {
					case 0 -> "Operand";
					case 1 -> "Labeled";
					case 2 -> "Type";
					case 3 -> "Scalar";
					case 4 -> "Address";
					case 5 -> "Register";
					case 6 -> "Op-Objects";
					case 7 -> "Operand Mask";
					case 8 -> "Masked Value";
					default -> "";
				};
			}
			int opIndex = column - 1;
			if (opIndex >= instruction.getNumOperands()) {
				return "";
			}
			return switch (row) {
				case 0 -> instruction.getDefaultOperandRepresentation(opIndex);
				case 1 -> CodeUnitFormat.DEFAULT.getOperandRepresentationList(instruction, opIndex);
				case 2 -> OperandType.toString(instruction.getOperandType(opIndex));
				case 3 -> instruction.getScalar(opIndex);
				case 4 -> {
					Address addr = instruction.getAddress(opIndex);
					yield addr != null ? addr.toString(true) : "";
				}
				case 5 -> instruction.getRegister(opIndex);
				case 6 -> getString(
					InstructionUtils.getFormatedOperandObjects(instruction, opIndex));
				case 7 -> debug != null ? debug.getFormattedInstructionMask(opIndex) : null;
				case 8 -> debug != null ? debug.getFormattedMaskedValue(opIndex) : null;
				default -> "";
			};
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			return false;
		}
	}

	private String getString(String strs[]) {
		if (strs == null) {
			return "-none-";
		}

		StringBuffer outStr = new StringBuffer();
		for (String str : strs) {
			if (outStr.length() != 0) {
				outStr.append(", ");
			}
			outStr.append(str.toString());
		}
		return outStr.toString();
	}
}
