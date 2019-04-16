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
//The script will use the first instructions in a selection and build a combined mask/value buffer.
//Memory is then searched looking for this combined value buffer that represents the selected instructions.
//This automates the process of searching through memory for a particular ordering of instructions by hand.
//@category Search.InstructionPattern

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;

public class SearchGuiSingle extends SearchBaseExtended {

	private JButton searchButton;
	private JCheckBox mnemonicCheckBox;
	private JCheckBox opOneCheckBox;
	private JCheckBox opTwoCheckBox;
	private JCheckBox constCheckBox;
	private JLabel jLabel1;
	private JPanel jPanel1;
	private JFrame frame;

	@Override
	public void run() throws Exception {
		initComponents();
	}

	private void initComponents() {

		frame = new JFrame();
		jPanel1 = new JPanel();
		mnemonicCheckBox = new GCheckBox("Mnemonics", true);
		opOneCheckBox = new GCheckBox("Operand 1", false);
		opTwoCheckBox = new GCheckBox("Operand 2", false);
		constCheckBox = new GCheckBox("Constants", false);
		searchButton = new JButton();
		jLabel1 = new GDLabel();

		GroupLayout jPanel1Layout = new GroupLayout(jPanel1);
		jPanel1.setLayout(jPanel1Layout);
		jPanel1Layout.setHorizontalGroup(
			jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGap(0, 100,
				Short.MAX_VALUE));
		jPanel1Layout.setVerticalGroup(
			jPanel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING).addGap(0, 100,
				Short.MAX_VALUE));

		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

		searchButton.setText("Search");
		searchButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				jButton1ActionPerformed(evt);
			}
		});

		jLabel1.setText("Search Parameters ...");

		GroupLayout layout = new GroupLayout(frame.getContentPane());
		frame.getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
			.addGroup(layout.createSequentialGroup() //
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
					.addGroup(layout.createSequentialGroup() //
						.addContainerGap() //
						.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
							.addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING) //
								.addComponent(opTwoCheckBox) //
								.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
									.addComponent(mnemonicCheckBox) //
									.addComponent(opOneCheckBox) //
								) //
							) //
							.addComponent(constCheckBox) //
							.addComponent(jLabel1) //
						) //
					) //
					.addGroup(layout.createSequentialGroup() //
						.addGap(32, 32, 32) //
						.addComponent(searchButton) //
					) //
				) //
				.addContainerGap(12, Short.MAX_VALUE) //
			) //
		);
		layout.setVerticalGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING) //
			.addGroup(layout.createSequentialGroup() //
				.addContainerGap() //
				.addComponent(jLabel1) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(mnemonicCheckBox) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(opOneCheckBox) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(opTwoCheckBox) //
				.addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED) //
				.addComponent(constCheckBox) //
				.addGap(18, 18, 18).addComponent(searchButton) //
				.addContainerGap(27, Short.MAX_VALUE) //
			) //
		);

		frame.pack();
		frame.setVisible(true);
	}

	private void jButton1ActionPerformed(ActionEvent evt) {

		SLMaskControl control = new SLMaskControl();

		this.clearResults();
		if (mnemonicCheckBox.isSelected()) {
			control.useMnemonic = true;
		}
		if (opOneCheckBox.isSelected()) {
			control.useOp1 = true;
		}
		if (opTwoCheckBox.isSelected()) {
			control.useOp2 = true;
		}
		if (constCheckBox.isSelected()) {
			control.useConst = true;
		}

		setState(control);
		loadSelectedInstructions();
		executeSearch();
		frame.dispose();
	}

}
