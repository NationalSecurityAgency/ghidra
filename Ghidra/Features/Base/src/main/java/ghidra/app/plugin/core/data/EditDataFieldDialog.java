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
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.util.Date;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.layout.PairLayout;

/**
 * Dialog for editing the name, comment, and datatype for a structure or union field.
 */
public class EditDataFieldDialog extends DialogComponentProvider {

	// These two fields are static so that the user's last choice is remembered across dialog uses.
	// The preferred way to do this would be to have a plugin manage this state and have that plugin
	// make the dialog available as a service.  At the time of writing, this solution seemed good
	// enough.  The downside of this is that these values are not saved across uses of Ghidra.
	private static boolean addAddress;
	private static boolean addDate;

	private JTextField nameField;
	private JTextField commentField;
	private DataTypeSelectionEditor dataTypeEditor;
	private JCheckBox addressCheckBox;
	private JCheckBox dateCheckBox;

	private PluginTool tool;
	private DataType newDataType;
	private DataTypeManagerService dtmService;

	private Composite composite;
	private Address address;
	private int ordinal;
	private Program program;

	/**
	 * Constructor 
	 * @param tool The tool hosting this dialog
	 * @param dtmService the DataTypeManagerService used for choosing datatypes
	 * @param composite the composite being edited
	 * @param program the program
	 * @param address the address of the data type component
	 * @param ordinal the ordinal of the data type component inside of the composite
	 */
	public EditDataFieldDialog(PluginTool tool, DataTypeManagerService dtmService,
			Composite composite, Program program, Address address, int ordinal) {

		super("Edit Field Dialog", true, true, true, false);

		this.tool = tool;
		this.dtmService = dtmService;
		this.composite = composite;
		this.program = program;
		this.address = address;
		this.ordinal = ordinal;

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
		tool = null;
		program = null;
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
	 * @return the text currently in the text field  for the field comment
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

		String name = getFieldName();
		nameField.setText(name);

		String comment = getComment();
		commentField.setText(comment);

		DataType dt = getComponentDataType();
		dataTypeEditor.setCellEditorValue(dt);

		if (addAddress) {
			addressCheckBox.setSelected(true);
			addTextToComment(getCurrentAddressString());
		}
		if (addDate) {
			dateCheckBox.setSelected(true);
			addTextToComment(getTodaysDate());
		}
	}

	private String getComment() {
		if (hasNoDataTypeComponent()) {
			return "";
		}

		DataTypeComponent dtc = composite.getComponent(ordinal);
		String comment = dtc.getComment();
		if (StringUtils.isBlank(comment)) {
			return "";
		}
		return comment;
	}

	private String getFieldName() {
		if (hasNoDataTypeComponent()) {
			return "";
		}

		DataTypeComponent dtc = composite.getComponent(ordinal);
		String fieldName = dtc.getFieldName();
		if (StringUtils.isBlank(fieldName)) {
			return "";
		}
		return fieldName;
	}

	private boolean hasNoDataTypeComponent() {
		return ordinal >= composite.getNumComponents();
	}

	@Override
	protected void okCallback() {
		if (updateComponent()) {
			close();
		}
	}

	private boolean updateComponent() {
		if (!hasChanges()) {
			return true;
		}
		Command<Program> cmd = new UpdateDataComponentCommand();
		if (!tool.execute(cmd, program)) {
			setStatusText(cmd.getStatusMsg(), MessageType.ERROR);
			return false;
		}
		return true;
	}

	private boolean hasChanges() {
		return hasNameChange() || hasCommentChange() || hasDataTypeChange();
	}

	private boolean hasCommentChange() {
		String oldComment = getComment();
		String newComment = getNewFieldComment();
		if (StringUtils.isBlank(newComment) && StringUtils.isBlank(oldComment)) {
			return false;
		}
		return !newComment.equals(oldComment);
	}

	private DataType getComponentDataType() {
		if (hasNoDataTypeComponent()) {
			return DataType.DEFAULT;
		}

		DataTypeComponent dtc = composite.getComponent(ordinal);
		return dtc.getDataType();
	}

	boolean hasDataTypeChange() {
		DataType oldDt = getComponentDataType();
		return newDataType != null && !newDataType.equals(oldDt);
	}

	boolean hasNameChange() {
		String newName = getNewFieldName();
		String currentName = getFieldName();
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
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildNameValuePanel(), BorderLayout.NORTH);
		panel.add(buildCheckboxPanel(), BorderLayout.SOUTH);
		return panel;
	}

	private JPanel buildCheckboxPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 30, 0));

		addressCheckBox = new JCheckBox("Add Current Address");
		addressCheckBox.addActionListener(this::addressCheckBoxChanged);

		dateCheckBox = new JCheckBox("Add Today's Date");
		dateCheckBox.addActionListener(this::dateCheckBoxChanged);

		panel.add(addressCheckBox);
		panel.add(dateCheckBox);
		return panel;
	}

	private JPanel buildNameValuePanel() {
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
		panel.add(new JLabel("Datatype:", SwingConstants.LEFT));
		panel.add(buildDataTypeChooserPanel());
		panel.add(new JLabel("Comment:", SwingConstants.LEFT));
		panel.add(commentField);

		return panel;
	}

	private JPanel buildDataTypeChooserPanel() {
		JPanel panel = new JPanel(new BorderLayout(10, 0));

		DataTypeManager dtm = composite.getDataTypeManager();
		dataTypeEditor = new DataTypeSelectionEditor(dtm, dtmService, AllowedDataTypes.ALL);

		JComponent editorComponent = dataTypeEditor.getEditorComponent();
		panel.add(editorComponent, BorderLayout.CENTER);

		return panel;
	}

	private void updateDataTypeTextField() {
		if (newDataType != null) {
			dataTypeEditor.setCellEditorValue(newDataType);
		}
		else {
			DataType dt = getComponentDataType();
			dataTypeEditor.setCellEditorValue(dt);
		}
	}

	private String generateTitle() {
		String compositeName = composite.getName();
		return "Edit " + compositeName + ", Field " + ordinal;
	}

	private void dateCheckBoxChanged(ActionEvent e) {
		String today = getTodaysDate();
		addDate = dateCheckBox.isSelected();
		if (addDate) {
			addTextToComment(today);
		}
		else {
			removeTextFromComment(today);
		}
	}

	private void addressCheckBoxChanged(ActionEvent e) {
		String addressString = getCurrentAddressString();
		addAddress = addressCheckBox.isSelected();
		if (addAddress) {
			addTextToComment(addressString);
		}
		else {
			removeTextFromComment(addressString);
		}
	}

	private void removeTextFromComment(String text) {
		String comment = commentField.getText().trim();
		int index = comment.indexOf(text);
		if (index < 0) {
			return;
		}

		// remove the given text and any spaces that follow it.
		comment = comment.replaceAll(text + "\\s*", "");
		commentField.setText(comment.trim());
	}

	private String getTodaysDate() {
		return DateUtils.formatCompactDate(new Date());
	}

	private String getCurrentAddressString() {
		return address.toString();
	}

	private void addTextToComment(String text) {
		String comment = commentField.getText().trim();
		if (comment.contains(text)) {
			return;
		}
		if (!comment.isBlank()) {
			comment += " ";
		}
		comment += text;
		commentField.setText(comment.trim());
	}

	public String getDataTypeText() {
		return dataTypeEditor.getCellEditorValueAsText();
	}

	private class UpdateDataComponentCommand implements Command<Program> {
		private String statusMessage = null;

		@Override
		public boolean applyTo(Program p) {

			maybeAdjustStructure();

			if (!updateDataType()) {
				return false;
			}
			if (!updateName()) {
				return false;
			}
			if (!updateComment()) {
				return false;
			}
			return true;
		}

		private void maybeAdjustStructure() {

			if (!(composite instanceof Structure struct)) {
				return;
			}

			int n = composite.getNumComponents();
			if (ordinal >= n) {
				int amount = ordinal - n;
				struct.growStructure(amount);
			}

			DataTypeComponent dtc = composite.getComponent(ordinal);
			if (dtc.getDataType() == DataType.DEFAULT) { // remove placeholder type
				DataType newtype = new Undefined1DataType();
				struct.replaceAtOffset(dtc.getOffset(), newtype, 1, "tempName",
					"Created by Edit Data Field action");
			}
		}

		private boolean updateName() {
			if (!hasNameChange()) {
				return true;
			}

			DataTypeComponent dtc = composite.getComponent(ordinal);
			try {
				dtc.setFieldName(getNewFieldName());
				return true;
			}
			catch (DuplicateNameException e) {
				statusMessage = "Duplicate field name";
				return false;
			}
		}

		private boolean updateComment() {
			DataTypeComponent dtc = composite.getComponent(ordinal);
			if (hasCommentChange()) {
				dtc.setComment(getNewFieldComment());
			}
			return true;
		}

		private boolean updateDataType() {

			if (!hasDataTypeChange()) {
				return true;
			}

			try {
				if (composite instanceof Structure struct) {
					updateStructure(struct);
				}
				else if (composite instanceof Union union) {
					updateUnion(union);
				}
				return true;
			}
			catch (DuplicateNameException e) {
				statusMessage = "Duplicate field name";
				return false;
			}
			catch (Exception e) {
				statusMessage = e.getMessage();
				return false;
			}
		}

		private void updateStructure(Structure struct) {
			DataTypeComponent dtc = composite.getComponent(ordinal);
			DataType resolvedDt = program.getDataTypeManager().resolve(newDataType, null);
			if (resolvedDt == DataType.DEFAULT) {
				struct.clearComponent(ordinal);
				return;
			}

			DataTypeInstance dti =
				DataTypeInstance.getDataTypeInstance(resolvedDt, -1, false);
			DataType dataType = dti.getDataType();
			int length = dti.getLength();
			String fieldName = dtc.getFieldName();
			String comment = dtc.getComment();
			dtc = struct.replace(ordinal, dataType, length, fieldName, comment);
		}

		private void updateUnion(Union union) throws DuplicateNameException {
			DataTypeComponent dtc = composite.getComponent(ordinal);
			DataType resolvedDt = program.getDataTypeManager().resolve(newDataType, null);
			String comment = dtc.getComment();
			String fieldName = dtc.getFieldName();
			union.insert(ordinal, resolvedDt);
			union.delete(ordinal + 1);
			dtc = union.getComponent(ordinal);
			dtc.setComment(comment);
			dtc.setFieldName(fieldName);
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
