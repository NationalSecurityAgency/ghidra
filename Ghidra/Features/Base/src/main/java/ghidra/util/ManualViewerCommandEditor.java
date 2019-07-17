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
package ghidra.util;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyEditorSupport;
import java.io.*;
import java.util.*;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.layout.PairLayout;

public class ManualViewerCommandEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String FILE_FORMAT_DESCRIPTION =
		"This determines the format of the " + "URL that is sent to the process above.  If " +
			ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING +
			" is chosen, then an HTTP URL will be passed to the process.  If " +
			ManualViewerCommandWrappedOption.FILE_URL_REPLACEMENT_STRING +
			" is chosen, the a File URL will be sent to " + "the process.  If " +
			ManualViewerCommandWrappedOption.FILENAME_REPLACEMENT_STRING +
			" is chosen, then only the file path will be sent to the process.";
	private static final String COMMAND_STRING_DESCRIPTION = "This is the name of, or a full " +
		"path to an executable that will be launched to open the processor manual.  " +
		"Examples include 'firefox', 'netscape', 'open', etc.";
	private static final String COMMAND_ARGUMENTS_DESCRIPTION =
		"These are the arguments that will " +
			"be passed to the command given in the 'Command String' field.";

	private static final String[] DESCRIPTIONS =
		{ FILE_FORMAT_DESCRIPTION, COMMAND_STRING_DESCRIPTION, COMMAND_ARGUMENTS_DESCRIPTION };

	private static final String FILE_FORMAT_LABEL = "File Format: ";
	private static final String COMMAND_ARGUMENTS_LABEL = "Command Arguments: ";
	private static final String COMMAND_STRING_LABEL = "Command String: ";

	private static final String[] NAMES =
		{ FILE_FORMAT_LABEL, COMMAND_STRING_LABEL, COMMAND_ARGUMENTS_LABEL };

	private ManualViewerCommandWrappedOption wrappedOption;
	private LaunchDataInputPanel editorComponent;

	private JTextField commandField;
	private JTextField argumentsField;
	private JComboBox<String> fileFormatComboBox;

	public ManualViewerCommandEditor() {
		editorComponent = new LaunchDataInputPanel();
	}

	@Override
	public String[] getOptionDescriptions() {
		return DESCRIPTIONS;
	}

	@Override
	public String[] getOptionNames() {
		return NAMES;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof ManualViewerCommandWrappedOption)) {
			return;
		}

		wrappedOption = (ManualViewerCommandWrappedOption) value;
		editorComponent.setOption(wrappedOption);
		firePropertyChange();
	}

	@Override
	public Object getValue() {
		return cloneCommandOptions();
	}

	private ManualViewerCommandWrappedOption cloneCommandOptions() {
		ManualViewerCommandWrappedOption newOption = new ManualViewerCommandWrappedOption();
		newOption.setCommandString(commandField.getText());

		try {
			newOption.setCommandArguments(parseArguments(argumentsField.getText()));
		}
		catch (Exception e) {
			Msg.showError(this, null, "Unable to Parse Command Arguments",
				"Unable to parse command arguments: " + argumentsField.getText(), e);
			return wrappedOption; // signal that the options haven't changed
		}
		newOption.setUrlReplacementString((String) fileFormatComboBox.getSelectedItem());
		return newOption;
	}

	private String[] parseArguments(String argumentString) throws IOException {
		StreamTokenizer tokenizer = new StreamTokenizer(new StringReader(argumentString));
		tokenizer.resetSyntax(); // don't use the defined values from the tokenizer's constructor    

		tokenizer.wordChars(33, 126);
		tokenizer.wordChars(128 + 32, 255);
		tokenizer.whitespaceChars(0, ' ');
		tokenizer.quoteChar('"');
		tokenizer.eolIsSignificant(false);
		tokenizer.slashSlashComments(false);
		tokenizer.slashStarComments(false);
		tokenizer.lowerCaseMode(false);

		List<String> argumentList = new ArrayList<>();
		int tokenType;
		while ((tokenType = tokenizer.nextToken()) != StreamTokenizer.TT_EOF) {
			// get all words
			if (tokenType == StreamTokenizer.TT_WORD) {
				argumentList.add(tokenizer.sval);
			}
			// get all numbers
			else if (tokenType == StreamTokenizer.TT_NUMBER) {
				argumentList.add(Double.toString(tokenizer.nval));
			}
			// get all quoted values
			else if (tokenizer.ttype == '"') {
				argumentList.add("\"" + tokenizer.sval + "\"");
			}
		}

		return argumentList.toArray(new String[argumentList.size()]);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class LaunchDataInputPanel extends JPanel {

		private LaunchDataInputPanel() {
			add(createWorkPanel());
		}

		void setOption(ManualViewerCommandWrappedOption option) {
			commandField.setText(option.getCommandString());
			String[] commandArguments = option.getCommandArguments();
			StringBuffer buffer = new StringBuffer();
			for (String string : commandArguments) {
				buffer.append(string);
				buffer.append(" ");
			}

			argumentsField.setText(buffer.toString().trim());

			fileFormatComboBox.setSelectedItem(option.getUrlReplacementString());
		}

		ManualViewerCommandWrappedOption getOption() {
			ManualViewerCommandWrappedOption option = new ManualViewerCommandWrappedOption();

			option.setCommandString(commandField.getText());

			String text = argumentsField.getText();
			StringTokenizer tokenizer = new StringTokenizer(text, " ");
			int size = tokenizer.countTokens();
			String[] arguments = new String[size];
			for (int i = 0; i < arguments.length; i++) {
				arguments[i] = tokenizer.nextToken();
			}
			option.setCommandArguments(arguments);

			option.setUrlReplacementString((String) fileFormatComboBox.getSelectedItem());

			return option;
		}

		private JComponent createWorkPanel() {
			JPanel workPanel = new JPanel();
			workPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
			workPanel.setLayout(new PairLayout());

			JLabel commandLabel = new GDLabel(COMMAND_STRING_LABEL);
			commandLabel.setToolTipText(COMMAND_STRING_DESCRIPTION);
			commandField = new JTextField(30);

			JLabel argumentsLabel = new GDLabel(COMMAND_ARGUMENTS_LABEL);
			argumentsLabel.setToolTipText(COMMAND_ARGUMENTS_DESCRIPTION);
			argumentsField = new JTextField(20);

			JLabel formatLabel = new GDLabel(FILE_FORMAT_LABEL);
			formatLabel.setToolTipText(FILE_FORMAT_DESCRIPTION);
			fileFormatComboBox = new GComboBox<>();
			fileFormatComboBox.addItem(
				ManualViewerCommandWrappedOption.HTTP_URL_REPLACEMENT_STRING);
			fileFormatComboBox.addItem(
				ManualViewerCommandWrappedOption.FILE_URL_REPLACEMENT_STRING);
			fileFormatComboBox.addItem(
				ManualViewerCommandWrappedOption.FILENAME_REPLACEMENT_STRING);
			fileFormatComboBox.setSelectedIndex(0);

			// add each grouping of widgets as a single line in the main panel's vertical layout;
			commandLabel.setHorizontalAlignment(SwingConstants.RIGHT);
			workPanel.add(commandLabel);
			workPanel.add(commandField);

			argumentsLabel.setHorizontalAlignment(SwingConstants.RIGHT);
			workPanel.add(argumentsLabel);
			workPanel.add(argumentsField);

			formatLabel.setHorizontalAlignment(SwingConstants.RIGHT);
			workPanel.add(formatLabel);
			workPanel.add(fileFormatComboBox);

			// listeners to trigger the apply button  
			commandField.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void changedUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}

				@Override
				public void removeUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}
			});

			argumentsField.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void changedUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}

				@Override
				public void removeUpdate(DocumentEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}
			});

			fileFormatComboBox.addItemListener(new ItemListener() {
				@Override
				public void itemStateChanged(ItemEvent e) {
					ManualViewerCommandEditor.this.firePropertyChange();
				}
			});

			return workPanel;
		}
	}
}
