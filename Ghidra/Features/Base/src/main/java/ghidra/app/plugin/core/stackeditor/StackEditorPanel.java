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

import java.awt.Component;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import ghidra.app.plugin.core.compositeeditor.CompositeEditorPanel;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.UsrException;

/**
 * Panel for editing a function stack.
 */
public class StackEditorPanel extends CompositeEditorPanel<StackFrameDataType, StackEditorModel> {

	private JTextField frameSizeField;
	private JTextField localSizeField;
	private JTextField paramSizeField;
	private JTextField paramOffsetField;
	private JTextField returnAddrOffsetField;
	private List<Component> focusList;

	public StackEditorPanel(Program program, StackEditorModel model, StackEditorProvider provider) {
		super(model, provider);
	}

	private StackEditorModel getStackModel() {
		return model;
	}

	@Override
	protected boolean hasUncomittedEntry() {
		// Stack editor has not yet been modified to use GFormattedTextField
		return false;
	}

	@Override
	protected boolean hasInvalidEntry() {
		// Stack editor has not yet been modified to use GFormattedTextField
		return false;
	}

	@Override
	protected void comitEntryChanges() {
		// do nothing
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

	@Override
	protected List<Component> getFocusComponents() {
		if (focusList == null) {
			//@formatter:off
			focusList = List.of(				
				table,
				searchPanel.getTextField(),				
				localSizeField,
				paramSizeField		
			);
			//@formatter:on
		}
		return focusList;
	}

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

		JPanel[] hPanels = new JPanel[] {
			createHorizontalPanel(
				new JPanel[] { frameSizePanel, returnAddrOffsetPanel, localSizePanel }),
			createHorizontalPanel(new JPanel[] { paramOffsetPanel, paramSizePanel }) };
		JPanel outerPanel = createVerticalPanel(hPanels);
		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		return outerPanel;
	}

	private void setupFrameSize() {
		frameSizeField = new JTextField(20);
		frameSizeField.setName("Frame Size");
		frameSizeField.setEditable(false);
		frameSizeField.setEnabled(false);
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
					getStackModel().setLocalSize(localSize);
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
				getStackModel().setParameterSize(paramSize);
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
		paramOffsetField.setEnabled(false);
	}

	private void setupReturnAddrOffset() {
		returnAddrOffsetField = new JTextField(20);
		returnAddrOffsetField.setName("Return Address Offset");
		returnAddrOffsetField.setEditable(false);
		returnAddrOffsetField.setEnabled(false);
	}

	@Override
	public void compositeInfoChanged() {
		adjustStackInfo();
	}

	private String getNumberString(int value) {
		return model.isShowingNumbersInHex() ? StackFrameDataType.getHexString(value, true)
				: Integer.toString(value);
	}

	private void adjustStackInfo() {
		StackFrameDataType editorStack = getStackModel().getEditorStack();

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

	@Override
	public void componentDataChanged() {
		provider.contextChanged();
	}

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
