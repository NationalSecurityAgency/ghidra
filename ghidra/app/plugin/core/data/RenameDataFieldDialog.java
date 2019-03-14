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
package ghidra.app.plugin.core.data;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.app.cmd.data.RenameDataFieldCmd;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;


class RenameDataFieldDialog extends DialogComponentProvider {

	private JComboBox<?> recentChoices;
	private JTextField choiceTextField;
	
	private DataTypeComponent component;
	private DataPlugin plugin;
	private Program program;

	RenameDataFieldDialog(DataPlugin plugin) {
		super("Rename Data Field", true, false, true, false);
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(plugin.getName(), "Rename_Data_Field"));
		addWorkPanel(create());

		addOKButton();
		addCancelButton();
	}

	public void setDataComponent(Program program, DataTypeComponent component, String name) {
		this.component = component;
		this.program = program;
		choiceTextField.setText(name);
		choiceTextField.selectAll();
	}

    @Override
    protected void okCallback() {
		close();
		
		RenameDataFieldCmd cmd = new RenameDataFieldCmd(component, choiceTextField.getText());
		plugin.getTool().execute(cmd, program);
		program = null;
    }

	@Override
	protected void cancelCallback() {
		program = null;
		close();
	}

    private JPanel create() {
		recentChoices = new GhidraComboBox<>();
        recentChoices.setEditable(true);

		JPanel mainPanel = new JPanel(new BorderLayout());
		JPanel topPanel = new JPanel(new BorderLayout());
		
		Border border = BorderFactory.createTitledBorder("Data Field Name");
		topPanel.setBorder(border);
			
		mainPanel.add(topPanel, BorderLayout.NORTH);

		topPanel.add(recentChoices, BorderLayout.NORTH);

        choiceTextField = (JTextField)recentChoices.getEditor().getEditorComponent();
        setFocusComponent(choiceTextField);
        choiceTextField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
        });
	    mainPanel.setBorder(new EmptyBorder(5,5,5,5));

		return mainPanel;
    }

}
