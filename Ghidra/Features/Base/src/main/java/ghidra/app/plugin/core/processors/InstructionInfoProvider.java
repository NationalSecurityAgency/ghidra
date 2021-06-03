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

import java.awt.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import docking.widgets.checkbox.GCheckBox;
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

/**
 * Component provider to show the instruction info. 
 *
 */
class InstructionInfoProvider extends ComponentProviderAdapter implements DomainObjectListener {
	private JPanel mainPanel;
	private JSplitPane pane;
	private ShowInstructionInfoPlugin plugin;
	private Program program;

	private JTextArea instructionText;
	private JTable opTable;

	private JCheckBox dynamicUpdateCB;

	private OperandModel operandModel;
	private Address myAddr;

	InstructionInfoProvider(ShowInstructionInfoPlugin plugin, boolean isDynamic) {
		super(plugin.getTool(), "Instruction Info", plugin.getName());
		this.plugin = plugin;

		buildMainPanel(isDynamic);
		setTransient();
		setWindowMenuGroup("Instruction Info");
		addToTool();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "Show_Instruction_Info_Window");
	}

	boolean dynamicUpdateSelected() {
		return dynamicUpdateCB.isSelected();
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

	/**
	 * Define the Main panel.
	 *
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel(boolean isDynamic) {

		mainPanel = new JPanel(new BorderLayout());

		instructionText = new JTextArea();
		Font defaultFont = instructionText.getFont();
		Font fixedWidthFont = new Font("monospaced", defaultFont.getStyle(), 14);
		instructionText.setFont(fixedWidthFont);
		instructionText.setEditable(false);

		operandModel = new OperandModel();
		opTable = new GhidraTable(operandModel);
		opTable.setFont(fixedWidthFont);
		opTable.setPreferredScrollableViewportSize(new Dimension(425, 105));
		//opTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		opTable.setRowSelectionAllowed(false);

		pane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(instructionText),
			new JScrollPane(opTable));
		pane.setResizeWeight(.25);
		mainPanel.add(pane, BorderLayout.CENTER);

		dynamicUpdateCB = new GCheckBox("Dynamic Update", isDynamic);
		dynamicUpdateCB.setAlignmentX(Component.CENTER_ALIGNMENT);
		dynamicUpdateCB.addItemListener(e -> dynamicStateChanged());

		mainPanel.add(dynamicUpdateCB, BorderLayout.SOUTH);
		mainPanel.validate();

		return mainPanel;
	}

	protected void dynamicStateChanged() {
		plugin.dynamicStateChanged(this, dynamicUpdateSelected());
	}

	void setAddress(Address address) {
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

	public void setNonDynamic() {
		dynamicUpdateCB.setSelected(false);
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
		 * @return the number of columns in the model
		 */
		@Override
		public int getColumnCount() {
			return instruction != null ? instruction.getNumOperands() + 1 : 0;
		}

		/**
		 * Returns the column name.
		 * @return a name for this column using the string value of the
		 * appropriate member in <I>columnIdentfiers</I>. If <I>columnIdentfiers</I>
		 * is null or does not have and entry for this index return the default
		 * name provided by the superclass.
		 */
		@Override
		public String getColumnName(int column) {
			if (column == 0) {
				return "";
			}
			return "Operand-" + column;
		}

		/**
		 * Returns the number of rows in this data table.
		 * @return the number of rows in the model
		 */
		@Override
		public int getRowCount() {
			return 9;
		}

		/**
		 * Returns an attribute value for the cell at <I>row</I>
		 * and <I>column</I>.
		 *
		 * @param   row             the row whose value is to be looked up
		 * @param   column          the column whose value is to be looked up
		 * @return                  the value Object at the specified cell
		 * @exception  ArrayIndexOutOfBoundsException  if an invalid row or
		 *               column was given.
		 */
		@Override
		public Object getValueAt(int row, int column) {
			if (instruction == null) {
				return null;
			}
			if (column == 0) {
				switch (row) {
					case 0:
						return "Operand";
					case 1:
						return "Labeled";
					case 2:
						return "Type";
					case 3:
						return "Scalar";
					case 4:
						return "Address";
					case 5:
						return "Register";
					case 6:
						return "Op-Objects";
					case 7:
						return "Operand Mask";
					case 8:
						return "Masked Value";
				}
			}
			int opIndex = column - 1;
			if (opIndex >= instruction.getNumOperands()) {
				return "";
			}
			switch (row) {
				case 0:
					return instruction.getDefaultOperandRepresentation(opIndex);
				case 1:
					return CodeUnitFormat.DEFAULT.getOperandRepresentationList(instruction,
						opIndex);
				case 2:
					return OperandType.toString(instruction.getOperandType(opIndex));
				case 3:
					return instruction.getScalar(opIndex);
				case 4:
					Address addr = instruction.getAddress(opIndex);
					return addr != null ? addr.toString(true) : "";
				case 5:
					return instruction.getRegister(opIndex);
				case 6:
					return getString(
						InstructionUtils.getFormatedOperandObjects(instruction, opIndex));
				case 7:
					return debug != null ? debug.getFormattedInstructionMask(opIndex) : null;
				case 8:
					return debug != null ? debug.getFormattedMaskedValue(opIndex) : null;
			}

			return "";
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
