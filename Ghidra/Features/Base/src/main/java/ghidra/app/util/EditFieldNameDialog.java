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
package ghidra.app.util;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.exception.DuplicateNameException;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import docking.ComponentProvider;
import docking.DialogComponentProvider;

public class EditFieldNameDialog extends DialogComponentProvider {

	private PluginTool tool;
	private TitledBorder nameBorder;
	private JTextField fieldName;
	
	private Program program;
	private DataTypeComponent dtComp;
	
   /**
	 * Construct a new dialog.
	 *
	 * @param title title for the dialog, null value is acceptable if no title
	 * @param tool the plugin tool
	 */
	public EditFieldNameDialog(String title, PluginTool tool) {
		super(title, true, true, true, false); 
		this.tool = tool;
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "EditFieldNameDialog"));

		addWorkPanel(create());

		setFocusComponent(fieldName);

		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
		
		setMinimumSize(new Dimension(300, 50));
	}
	
	
	
	private String getCurrentFieldName() {
		String name = dtComp.getFieldName();
		if (name == null) {
			name = dtComp.getDefaultFieldName();
		}
		return name;
	}

	/**
	 * This method gets called when the user clicks on the OK Button.  The base
	 * class calls this method.
	 */
    @Override
    protected void okCallback() {
   	
        String newName = fieldName.getText().trim();
        
        if (newName.equals(getCurrentFieldName())) {
        	close();
        	return;
        }
        
        boolean success = false;
        int txId = program.startTransaction("Edit Field Name");
        try {
			dtComp.setFieldName(newName);
			DataType parent = dtComp.getParent();
			if (parent != null) {
				long timeNow = System.currentTimeMillis();
	    		parent.setLastChangeTime(timeNow);
			}
			success = true;
		} catch (DuplicateNameException e) {
			setStatusText(e.getMessage());
		} finally {
			program.endTransaction(txId, true);
		}
		
		if (success) {
			dtComp = null;
			program = null;
			close();
		}
    }
    
	public void editField(DataTypeComponent dataTypeComponent, Program p) {
		ComponentProvider componentProvider = tool.getComponentProvider(PluginConstants.CODE_BROWSER);
		JComponent component = componentProvider.getComponent();
		editField( dataTypeComponent, p, component );
	}	
	
	public void editField(DataTypeComponent dataTypeComponent, Program p, Component centeredOverComponent ) {
	    this.dtComp = dataTypeComponent;
        this.program = p;
        String name = getCurrentFieldName();
        setTitle("Edit Field Name: "+ dataTypeComponent.getParent().getName() + "." + name);
        fieldName.setText(name);
        clearStatusText();
        tool.showDialog(this, centeredOverComponent);
	}
	
	/**
	 * Define the Main panel for the dialog here.
	 */
	private JPanel create() {
		fieldName = new JTextField();
		
		JPanel mainPanel = new JPanel(new BorderLayout());

		nameBorder = BorderFactory.createTitledBorder("Enter Field Name");
		mainPanel.setBorder(nameBorder);
		
		mainPanel.add(fieldName, BorderLayout.CENTER);
	    
		mainPanel.setBorder(new EmptyBorder(5,5,5,5));

		return mainPanel;
	}

}
