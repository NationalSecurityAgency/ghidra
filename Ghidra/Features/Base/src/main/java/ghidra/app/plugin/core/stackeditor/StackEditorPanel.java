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
package ghidra.app.plugin.core.stackeditor;

import java.awt.event.*;

import javax.swing.*;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.compositeeditor.CompositeEditorPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.UsrException;

/**
 * Panel for editing a function stack.
 */
public class StackEditorPanel extends CompositeEditorPanel {

	private JTextField frameSizeField;
	private JTextField localSizeField;
	private JTextField paramSizeField;
	private JTextField paramOffsetField;
	private JTextField returnAddrOffsetField;

	public StackEditorPanel(Program program, StackEditorModel model, StackEditorProvider provider) {
		super(model, provider);
	}

	int getFrameSize() {
		return Integer.decode(frameSizeField.getText()).intValue();
	}

	int getLocalSize() {
		return Integer.decode(localSizeField.getText()).intValue();
	}

	int getParamSize() {
		return Integer.decode(paramSizeField.getText()).intValue();
	}

	int getParamOffset() {
		return Integer.decode(paramOffsetField.getText()).intValue();
	}

	int getReturnAddrOffset() {
		return Integer.decode(returnAddrOffsetField.getText()).intValue();
	}

	/*
	 *  (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorPanel#createInfoPanel()
	 */
	@Override
	protected JPanel createInfoPanel() {

		this.setBorder(BEVELED_BORDER);

		setupFrameSize();
		setupLocalSize();
		setupParamSize();
		setupParamOffset();
		setupReturnAddrOffset();
		adjustStackInfo();
		JPanel frameSizePanel = createNamedTextPanel(frameSizeField, "Frame Size");
		JPanel localSizePanel = createNamedTextPanel(localSizeField, "Local Size");
		JPanel paramSizePanel = createNamedTextPanel(paramSizeField, "Parameter Size");
		JPanel paramOffsetPanel = createNamedTextPanel(paramOffsetField, "Parameter Offset");
		JPanel returnAddrOffsetPanel =
			createNamedTextPanel(returnAddrOffsetField, "Return Address Offset");

		JPanel[] hPanels =
			new JPanel[] {
				createHorizontalPanel(new JPanel[] { frameSizePanel, returnAddrOffsetPanel,
					localSizePanel }),
				createHorizontalPanel(new JPanel[] { paramOffsetPanel, paramSizePanel }) };
		JPanel outerPanel = createVerticalPanel(hPanels);
		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return outerPanel;
	}

	private void setupFrameSize() {
		frameSizeField = new JTextField(20);
		frameSizeField.setName("Frame Size");
		frameSizeField.setEditable(false);
	}

	private void setupLocalSize() {
		localSizeField = new JTextField(20);
		localSizeField.setName("Local Size");
		localSizeField.setEditable(true);
		localSizeField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedLocalSize();
			}
		});
		localSizeField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// don't care
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedLocalSize();
			}
		});
	}

	private void updatedLocalSize() {
		String valueStr = localSizeField.getText();
		Integer value;
		try {
			value = Integer.decode(valueStr);
			int localSize = value.intValue();
			if (localSize < 0) {
				model.setStatus("Local size cannot be negative.", true);
			}
			else {
				try {
					((StackEditorModel) model).setLocalSize(localSize);
				}
				catch (UsrException ue) {
					model.setStatus("Invalid local size \"" + valueStr + "\". " + ue.getMessage(),
						true);
				}
			}
		}
		catch (NumberFormatException e1) {
			model.setStatus("Invalid local size \"" + valueStr + "\".", true);
		}
		compositeInfoChanged();
	}

	private void setupParamSize() {
		paramSizeField = new JTextField(20);
		paramSizeField.setName("Parameter Size");
		paramSizeField.setEditable(true);
		paramSizeField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updatedParamSize();
			}
		});
		paramSizeField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// don't care
			}

			@Override
			public void focusLost(FocusEvent e) {
				updatedParamSize();
			}
		});
	}

	private void updatedParamSize() {
		String valueStr = paramSizeField.getText();
		Integer value;
		try {
			value = Integer.decode(valueStr);
			int paramSize = value.intValue();
			try {
				((StackEditorModel) model).setParameterSize(paramSize);
			}
			catch (UsrException ue) {
				model.setStatus("Invalid parameter size \"" + valueStr + "\". " + ue.getMessage(),
					true);
			}
		}
		catch (NumberFormatException e1) {
			model.setStatus("Invalid parameter size \"" + valueStr + "\".", true);
		}
		compositeInfoChanged();
	}

	private void setupParamOffset() {
		paramOffsetField = new JTextField(20);
		paramOffsetField.setName("Parameter Offset");
		paramOffsetField.setEditable(false);
	}

	private void setupReturnAddrOffset() {
		returnAddrOffsetField = new JTextField(20);
		returnAddrOffsetField.setName("Return Address Offset");
		returnAddrOffsetField.setEditable(false);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeModelDataListener#compositeInfoChanged()
	 */
	@Override
	public void compositeInfoChanged() {
		adjustStackInfo();
	}

	private String getNumberString(int value) {
		return model.isShowingNumbersInHex() ? StackFrameDataType.getHexString(value, true)
				: Integer.toString(value);
	}

	/**
	 * 
	 */
	private void adjustStackInfo() {
		StackFrameDataType editorStack = ((StackEditorModel) model).getEditorStack();

		String frameSize = getNumberString(editorStack.getFrameSize());
		if (!frameSizeField.getText().trim().equals(frameSize)) {
			frameSizeField.setText(frameSize);
		}

		String localSize = getNumberString(editorStack.getLocalSize());
		if (!localSizeField.getText().trim().equals(localSize)) {
			localSizeField.setText(localSize);
		}

		String paramSize = getNumberString(editorStack.getParameterSize());
		if (!paramSizeField.getText().trim().equals(paramSize)) {
			paramSizeField.setText(paramSize);
		}

		String paramOffset = getNumberString(editorStack.getParameterOffset());
		if (!paramOffsetField.getText().trim().equals(paramOffset)) {
			paramOffsetField.setText(paramOffset);
		}

		String returnAddressOffset = getNumberString(editorStack.getReturnAddressOffset());
		if (!returnAddrOffsetField.getText().trim().equals(returnAddressOffset)) {
			returnAddrOffsetField.setText(returnAddressOffset);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeViewerModelListener#componentDataChanged()
	 */
	@Override
	public void componentDataChanged() {
		// Don't need to update other than table when component data changes.
	}

	@Override
	public void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		boolean reload = true;
		String objectType = "domain object";
		if (domainObject instanceof Program) {
			objectType = "program";
		}
		else if (domainObject instanceof DataTypeArchive) {
			objectType = "data type archive";
		}
		DataTypeManager dtm = ((StackEditorModel) model).getOriginalDataTypeManager();
		Composite originalDt = ((StackEditorModel) model).getOriginalComposite();
		if (originalDt instanceof StackFrameDataType) {
			StackFrameDataType sfdt = (StackFrameDataType) originalDt;
			Function function = sfdt.getFunction();
			if (function.isDeleted()) {
				// Cancel Editor.
				provider.dispose();
				PluginTool tool = ((StackEditorProvider) provider).getPlugin().getTool();
				tool.setStatusInfo("Stack Editor was closed for " + provider.getName());
				return;
			}
			StackFrame stack = function.getStackFrame();
			StackFrameDataType newSfdt = new StackFrameDataType(stack, dtm);
			if (!newSfdt.equals(((StackEditorModel) model).getViewComposite())) {
				originalDt = newSfdt;
			}
		}
		((StackEditorModel) model).updateAndCheckChangeState();
		if (model.hasChanges()) {
			String name = ((StackEditorModel) model).getTypeName();
			// The user has modified the structure so prompt for whether or
			// not to reload the structure.
			String question =
				"The " + objectType + " \"" + domainObject.getName() + "\" has been restored.\n" +
					"\"" + model.getCompositeName() + "\" may have changed outside the editor.\n" +
					"Discard edits & reload the " + name + " Editor?";
			String title = "Reload " + name + " Editor?";
			int response = OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, title, question);
			if (response != 1) {
				reload = false;
			}
		}
		if (reload) {
			cancelCellEditing();
			// TODO
//			boolean lockState = model.isLocked(); // save the lock state
			model.load(originalDt, model.isOffline()); // reload the structure
//			model.setLocked(lockState); // restore the lock state
			model.updateAndCheckChangeState();
		}
		else {
			((StackEditorModel) model).refresh();
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.compositeeditor.CompositeEditorPanel#dispose()
	 */
	@Override
	public void dispose() {
		removeFocusListeners(localSizeField);
		removeFocusListeners(paramSizeField);
		removeFocusListeners(paramOffsetField);
		removeFocusListeners(returnAddrOffsetField);
		super.dispose();
	}

	private void removeFocusListeners(JTextField textField) {
		FocusListener[] fl = textField.getFocusListeners();
		for (FocusListener element : fl) {
			textField.removeFocusListener(element);
		}
	}

	@Override
	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		// TODO Auto-generated method stub

	}

	@Override
	protected void adjustCompositeInfo() {
		// TODO Auto-generated method stub

	}

}
