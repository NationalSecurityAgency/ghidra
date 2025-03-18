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

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.button.BrowseButton;
import ghidra.app.cmd.data.CreateDataInStructureCmd;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for editing the name, comment, and datatype for a structure or union field.
 */
public class EditDataFieldDialog extends DialogComponentProvider {

	private JTextField nameField;
	private JTextField commentField;
	private JTextField dataTypeTextField;

	private DataTypeComponent component;
	private PluginTool tool;
	private DataType newDataType;
	private ProgramLocation programLocation;
	private DataTypeManagerService dtmService;

	/**
	 * Constructor
	 * @param tool The tool hosting this dialog
	 * @param dtmService the DataTypeManagerService used for choosing datatypes
	 * @param location the location of the field being edited
	 * @param dataTypeComponent the component of the field being edited
	 */
	public EditDataFieldDialog(PluginTool tool, DataTypeManagerService dtmService,
			ProgramLocation location, DataTypeComponent dataTypeComponent) {
		super("Edit Field Dialog", true, true, true, false);
		this.tool = tool;
		this.dtmService = dtmService;
		this.programLocation = location;
		this.component = dataTypeComponent;
		setTitle(generateTitle());

		addWorkPanel(buildMainPanel());
		initializeFields();
		setFocusComponent(nameField);
		setHelpLocation(new HelpLocation("DataPlugin", "Edit_Field_Dialog"));

		addOKButton();
		addCancelButton();
	}

	@Override
	public void dispose() {
		super.dispose();
		programLocation = null;
		component = null;
		tool = null;
	}

	/**
	 * Returns the pending new datatype to change to.
	 * @return the pending new datatype to change to
	 */
	public DataType getNewDataType() {
		return newDataType != null ? newDataType : new Undefined1DataType();
	}

	/**
	 * Returns the text currently in the text field  for the field name.
	 * @return the text currently in the text field  for the field name
	 */
	public String getNameText() {
		return nameField.getText();
	}

	/**
	 * Sets the dialog's name text field to the given text.
	 * @param newName the text to put into the name text field
	 */
	public void setNameText(String newName) {
		nameField.setText(newName);
	}

	/**
	 * Returns the text currently in the text field for the field comment.
	 * @return the text currently in the text field  for the field commment
	 */
	public String getCommentText() {
		return commentField.getText();
	}

	/**
	 * Sets the dialog's comment text field to the given text.
	 * @param newComment the text to put into the comment text field
	 */
	public void setCommentText(String newComment) {
		commentField.setText(newComment);
	}

	/**
	 * Sets the pending new datatype and updates the datatype text field to the name of that
	 * datatype.
	 * @param dataType the new pending datatype
	 */
	public void setDataType(DataType dataType) {
		newDataType = dataType;
		updateDataTypeTextField();
	}

	private void initializeFields() {
		String name = component.getFieldName();
		if (StringUtils.isBlank(name)) {
			name = "";
		}
		nameField.setText(name);
		commentField.setText(component.getComment());
		dataTypeTextField.setText(component.getDataType().getDisplayName());
	}

	@Override
	protected void okCallback() {
		if (updateComponent()) {
			close();
			programLocation = null;
		}
	}

	private boolean updateComponent() {
		if (!hasChanges()) {
			return true;
		}
		Command<Program> cmd = new UpdateDataComponentCommand();
		if (!tool.execute(cmd, programLocation.getProgram())) {
			setStatusText(cmd.getStatusMsg(), MessageType.ERROR);
			return false;
		}
		return true;
	}

	private boolean hasChanges() {
		return hasNameChange() || hasCommentChange() || hasDataTypeChange();
	}

	private boolean hasCommentChange() {
		String newComment = getNewFieldComment();
		if (StringUtils.isBlank(newComment) && StringUtils.isBlank(component.getComment())) {
			return false;
		}
		return !newComment.equals(component.getComment());
	}

	boolean hasDataTypeChange() {
		return newDataType != null && !newDataType.equals(component.getDataType());
	}

	boolean hasNameChange() {
		String newName = getNewFieldName();
		String currentName = component.getFieldName();
		if (currentName == null) {
			currentName = component.getDefaultFieldName();
		}
		if (newName.equals(currentName)) {
			return false;
		}
		return true;
	}

	private String getNewFieldName() {
		return nameField.getText().trim();
	}

	private String getNewFieldComment() {
		return commentField.getText().trim();
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

		nameField = new JTextField(20);
		nameField.setEditable(true);
		nameField.addActionListener(e -> okCallback());
		commentField = new JTextField(20);
		commentField.setEditable(true);
		commentField.addActionListener(e -> okCallback());

		panel.add(new JLabel("Field Name:", SwingConstants.LEFT));
		panel.add(nameField);
		panel.add(new JLabel("Comment:", SwingConstants.LEFT));
		panel.add(commentField);
		panel.add(new JLabel("Datatype:", SwingConstants.LEFT));
		panel.add(buildDataTypeChooserPanel());

		return panel;
	}

	private JPanel buildDataTypeChooserPanel() {
		JPanel panel = new JPanel(new BorderLayout(10, 0));

		dataTypeTextField = new JTextField();
		dataTypeTextField.setEditable(false);
		BrowseButton browseButton = new BrowseButton();
		browseButton.setToolTipText("Browse the Data Manager");
		browseButton.addActionListener(e -> showDataTypeBrowser());

		panel.add(dataTypeTextField, BorderLayout.CENTER);
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	private void showDataTypeBrowser() {
		newDataType = dtmService.getDataType("");
		updateDataTypeTextField();
	}

	private void updateDataTypeTextField() {
		if (newDataType != null) {
			dataTypeTextField.setText(newDataType.getDisplayName());
		}
		else {
			dataTypeTextField.setText(component.getDataType().getDisplayName());
		}
	}

	private String generateTitle() {
		DataType parent = component.getParent();
		String compositeName = parent.getName();
		return "Edit " + compositeName + ", Field " + component.getOrdinal();
	}

	public String getDataTypeText() {
		return dataTypeTextField.getText();
	}

	private class UpdateDataComponentCommand implements Command<Program> {
		private String statusMessage = null;

		@Override
		public boolean applyTo(Program program) {
			if (component.isUndefined() || hasDataTypeChange()) {
				DataType dt = getNewDataType();
				Address address = programLocation.getAddress();
				int[] path = programLocation.getComponentPath();
				Command<Program> cmd = new CreateDataInStructureCmd(address, path, dt, false);
				if (!cmd.applyTo(program)) {
					statusMessage = cmd.getStatusMsg();
					return false;
				}
				component = DataTypeUtils.getDataTypeComponent(program, address, path);
			}
			if (hasNameChange()) {
				try {
					component.setFieldName(getNewFieldName());
				}
				catch (DuplicateNameException e) {
					statusMessage = "Duplicate field name";
					return false;
				}
			}
			if (hasCommentChange()) {
				component.setComment(getNewFieldComment());
			}
			return true;
		}

		@Override
		public String getStatusMsg() {
			return statusMessage;
		}

		@Override
		public String getName() {
			return "Update Structure Field";
		}

	}

}
