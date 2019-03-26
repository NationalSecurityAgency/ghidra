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
//The script will use a selection of multiple instructions and build a combined mask/value buffer.
//Memory is then searched looking for this combined value buffer that represents the selected instructions.
//This automates the process of searching through memory for a particular ordering of instructions by hand.
//@category Search.InstructionPattern

import java.awt.Color;
import java.awt.Component;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

public class SearchGuiMulti extends SearchBaseExtended {

	private JScrollPane jScrollPane1;
	private JTable jTable1;
	private JToggleButton mnemonicButton;
	private JToggleButton op1Button;
	private JToggleButton op2Button;
	private JButton searchButton;
	private JFrame frame;

	private DefaultTableModel tableModel;

	DataObject[][] tableContentsDO = null;

	private int num_columns = 4;
	private Object[] columnIdentifiers =
		new Object[] { "Mnemonic", "Operand 1", "Operand 2", "Operand 3" };

	@Override
	public void run() {
		loadSelectedInstructions();//populate the mnemonic and ops structures
		initComponents();//sets up the gui and listeners
	}

	// <editor-fold defaultstate="collapsed" desc="Generated Code">                          
	private void initComponents() {

		mnemonicButton = new JToggleButton();
		op1Button = new JToggleButton();
		op2Button = new JToggleButton();
		jScrollPane1 = new JScrollPane();
		jTable1 = new JTable();

		searchButton = new JButton();
		frame = new JFrame("Multi-Grain Search");

		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

		mnemonicButton.setText("Mnemonic");
		mnemonicButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				mnemonicButtonActionPerformed(evt);
			}
		});
		mnemonicButton.setVisible(false);

		op1Button.setText("Operand 1");
		op1Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				op1ButtonActionPerformed(evt);
			}
		});
		op1Button.setVisible(false);

		op2Button.setText("Operand 2");
		op2Button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				op2ButtonActionPerformed(evt);
			}
		});
		op2Button.setVisible(false);

		searchButton.setText("Search");
		searchButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				searchButtonActionPerformed(evt);
			}
		});

		fillTable();
		tableModel = new DefaultTableModel(tableContentsDO, columnIdentifiers) {

			@Override
			public Class<?> getColumnClass(int columnIndex) {
				return DataObject.class;
			}
		};

		jTable1.setModel(tableModel);

		DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value,
					boolean isSelected, boolean hasFocus, int row, int column) {

				DataObject dataObject = (DataObject) value;
				String data = dataObject.getData();
				JLabel theRenderer = (JLabel) super.getTableCellRendererComponent(table, data,
					isSelected, hasFocus, row, column);

				Color backgroundColor = dataObject.getBackgroundColor();
				if (backgroundColor != null) {
					if (isSelected) {
						theRenderer.setBackground(backgroundColor.darker());
					}
					else {
						theRenderer.setBackground(backgroundColor);
					}
				}

				return theRenderer;
			}
		};

		jTable1.setDefaultRenderer(DataObject.class, renderer);

		jTable1.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				jTable1MouseClicked(evt);
			}
		});

		jScrollPane1.setViewportView(jTable1);

		searchButton.setText("Search");

		mnemonicButton.setSize(20, 10);

		GroupLayout layout = new GroupLayout(frame.getContentPane());
		frame.getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
			.addGroup(layout.createSequentialGroup() //
				.addContainerGap(15, Short.MAX_VALUE) //
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
					.addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup() //
						.addComponent(jScrollPane1, GroupLayout.PREFERRED_SIZE, 357,
							GroupLayout.PREFERRED_SIZE) //
						.addContainerGap() //
					) // 
					.addGroup(GroupLayout.Alignment.CENTER, layout.createSequentialGroup() //
						.addComponent(mnemonicButton) //
						.addGap(39, 39, 39) //
						.addComponent(op1Button) //
						.addGap(42, 42, 42) //
						.addComponent(op2Button) //
						.addGap(40, 40, 40) //
					) //
				) //
			) //
			.addGroup(layout.createSequentialGroup() //
				.addGap(153, 153, 153) //
				.addComponent(searchButton) //
				.addContainerGap(164, Short.MAX_VALUE) //
			) //
		);
		layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
			.addGroup(layout.createSequentialGroup() //
				.addGap(23, 23, 23) //
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE) //
					.addComponent(op1Button) //
					.addComponent(op2Button) //
					.addComponent(mnemonicButton) //
				) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(jScrollPane1, GroupLayout.PREFERRED_SIZE, 402,
					GroupLayout.PREFERRED_SIZE) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(searchButton) //
				.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE) //
			) //
		);

		frame.pack();
		frame.setVisible(true);
	}

	private void fillTable() {
		tableContentsDO = new DataObject[mnemonics.size()][num_columns];

		for (int mnemonic = 0; mnemonic < mnemonics.size(); mnemonic++) {
			for (int column = 0; column < num_columns; column++) {

				if (column == 0) {
					tableContentsDO[mnemonic][column] =
						new DataObject(mnemonics.get(mnemonic).textRep, Color.green);
				}
				else {
					OperandCase temp = null;
					try {
						temp = ops.get(column - 1).get(mnemonics.get(mnemonic));
					}
					catch (Exception a) {
						temp = null;
					}
					if (temp != null) {
						tableContentsDO[mnemonic][column] =
							new DataObject(temp.textRep, Color.red.brighter());
					}
					else {
						tableContentsDO[mnemonic][column] = new DataObject("", Color.white);
					}
				}

			}
		}
	}

	private void jTable1MouseClicked(MouseEvent evt) {
		int rowSelection = jTable1.getSelectedRow();
		int columnSelection = jTable1.getSelectedColumn();

		if (rowSelection < 0 || rowSelection >= jTable1.getRowCount()) {
			throw new IndexOutOfBoundsException();
		}
		if (columnSelection < 0 || columnSelection >= jTable1.getColumnCount()) {
			throw new IndexOutOfBoundsException();
		}

		if (tableContentsDO[rowSelection][columnSelection].getBackgroundColor().equals(
			Color.green)) {
			tableContentsDO[rowSelection][columnSelection].setBackgroundColor(Color.red);
		}
		else if (tableContentsDO[rowSelection][columnSelection].getBackgroundColor().equals(
			Color.red)) {
			tableContentsDO[rowSelection][columnSelection].setBackgroundColor(Color.green);
		}
		else {
			//TODO Determine what to do if the cell is white when clicked on. White cell means that there isn't an operand or mnemonic in that position.
		}
		jTable1.repaint();
	}

	private void mnemonicButtonActionPerformed(ActionEvent evt) {

		int selectedRow = jTable1.getSelectedRow();

		if (mnemonicButton.isSelected()) {
			tableContentsDO[selectedRow][0].setBackgroundColor(Color.red);
		}
		else {//off when clicked, turn on and update the table to reflect being enabled
			tableContentsDO[selectedRow][0].setBackgroundColor(Color.green);
		}
		jTable1.repaint();
	}

	private void op1ButtonActionPerformed(ActionEvent evt) {

		int selectedRow = jTable1.getSelectedRow();

		if (op1Button.isSelected()) {
			tableContentsDO[selectedRow][1].setBackgroundColor(Color.red);
		}
		else {//off when clicked, turn on and update the table to reflect being enabled
			tableContentsDO[selectedRow][1].setBackgroundColor(Color.green);
		}
		jTable1.repaint();
	}

	private void op2ButtonActionPerformed(ActionEvent evt) {

		int selectedRow = jTable1.getSelectedRow();

		if (op2Button.isSelected()) {
			tableContentsDO[selectedRow][2].setBackgroundColor(Color.red);
		}
		else {//off when clicked, turn on and update the table to reflect being enabled
			tableContentsDO[selectedRow][2].setBackgroundColor(Color.green);
		}
		jTable1.repaint();
	}

	private void searchButtonActionPerformed(ActionEvent evt) {
		//build the filter controlList
		//Set state of the search
		//execute the searchArrays

		for (int row = 0; row < mnemonics.size(); row++) {
			SLMaskControl temp = new SLMaskControl();

			if (tableContentsDO[row][0].getBackgroundColor().equals(Color.green)) {
				temp.useMnemonic = true;
			}
			else {
				temp.useMnemonic = false;
			}

			if (tableContentsDO[row][1].getBackgroundColor().equals(Color.green)) {
				temp.useOp1 = true;
				if (ops.get(0).get(mnemonics.get(row)).constant) {
					temp.useConst = true;
				}
			}
			else {
				temp.useOp1 = false;
			}

			if (tableContentsDO[row][2].getBackgroundColor().equals(Color.green)) {
				temp.useOp2 = true;
				if (ops.get(1).get(mnemonics.get(row)).constant) {
					temp.useConst = true;
				}
			}
			else {
				temp.useOp2 = false;
			}

			controlList.add(temp);
		}

		executeSearch();
		frame.dispose();
	}

	private class DataObject {
		private String data;
		private Color background = Color.white;

		public DataObject(String data, Color color) {
			this.data = data;
			this.background = color;
		}

		String getData() {
			return data;
		}

		Color getBackgroundColor() {
			return background;
		}

		void setBackgroundColor(Color newBackground) {
			this.background = newBackground;
		}

		@Override
		public String toString() {
			return data;
		}
	}

}
