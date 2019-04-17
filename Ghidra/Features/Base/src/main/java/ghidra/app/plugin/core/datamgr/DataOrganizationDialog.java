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
package ghidra.app.plugin.core.datamgr;

import java.awt.BorderLayout;

import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import ghidra.program.model.data.*;

/**
 * The DataOrganizationDialog
 */
public class DataOrganizationDialog extends DialogComponentProvider {

	private static String TITLE = "Data Type Alignment";
	private DataTypeManager dataTypeManager;
	private DataOrganization dataOrganization;
	private JPanel mainPanel;
	private DataOrganizationPanel alignPanel;
	private SizeAlignmentPanel sizePanel;
    private boolean actionComplete;
	
	/**
	 * Creates a data type organization dialog for specifying data type alignment information 
	 * for a single data type manager. This dialog allows the user to align all data types in
	 * the associated data type manager.
	 * @param dataTypeManager the data type manager
	 * @param dataOrganization structure containing the alignment information. 
	 * This object will be modified by the information entered into the dialog.
	 */
	public DataOrganizationDialog(DataTypeManager dataTypeManager,
			DataOrganizationImpl dataOrganization) {
        super(TITLE, true);
        this.dataTypeManager = dataTypeManager;
        this.dataOrganization = dataOrganization;
		
		JPanel headerPanel = new JPanel();
		headerPanel.add(new JLabel("<HTML>Alignment Information for <b>" + 
				dataTypeManager.getName() + "</b>.</HTML>"));
		
		alignPanel = new DataOrganizationPanel();
		alignPanel.setOrganization(dataOrganization);
		sizePanel = new SizeAlignmentPanel();
		sizePanel.setOrganization(dataOrganization);
		
		JPanel infoPanel = new JPanel(new BorderLayout());
		infoPanel.add(alignPanel, BorderLayout.NORTH);
		infoPanel.add(sizePanel, BorderLayout.CENTER);
        
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(infoPanel, BorderLayout.CENTER);
        addWorkPanel(mainPanel);
        initialize();
    }

    private void initialize() {
    	actionComplete = false;
    	addOKButton();
    	setOkButtonText("Set");
        addCancelButton();
//        setHelpLocation(new HelpLocation(plugin, "Align_Data_Types_In_Archive"));
    }
    
    public boolean userCanceled() {
        return !actionComplete && !isVisible(); 
    }

	@Override
	protected void okCallback() {
        actionComplete = true;
		close();
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
        actionComplete = false;
	}

	public DataOrganization getDataOrganization() {
		return dataOrganization;
	}
}
