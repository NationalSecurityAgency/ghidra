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
package ghidra.app.util.viewer.field;

import java.awt.Component;
import java.beans.PropertyEditorSupport;

import javax.swing.JPanel;
import javax.swing.SwingConstants;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.PairLayout;

/**
 * Provides a custom GUI layout for the File Offset field options
 */
public class FileOffsetFieldOptionsPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String SHOW_FILENAME_LABEL = "Show Filename";
	private static final String USE_HEX_LABEL = "Show Numbers In Hex";

	private static final String[] NAMES = { SHOW_FILENAME_LABEL, USE_HEX_LABEL };

	private static final String SHOW_FILENAME_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Prepends the filename to the file offset in the File Offset field.", 75);
	private static final String USE_HEX_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Toggles displaying file offsets in hexadecimal/decimal in the File Offset field.", 75);

	private static final String[] DESCRIPTIONS = { SHOW_FILENAME_TOOLTIP, USE_HEX_TOOLTIP };

	private FileOffsetFieldOptionsWrappedOption option;

	private Component editorComponent;
	private GCheckBox showFilenameCheckbox;
	private GCheckBox useHexCheckbox;

	/**
	 * Creates a new {@link FileOffsetFieldOptionsPropertyEditor}
	 */
	public FileOffsetFieldOptionsPropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new PairLayout(6, 10));

		GDLabel showFilenameLabel = new GDLabel(SHOW_FILENAME_LABEL, SwingConstants.RIGHT);
		showFilenameLabel.setToolTipText(SHOW_FILENAME_TOOLTIP);
		panel.add(showFilenameLabel);
		showFilenameCheckbox = new GCheckBox();
		showFilenameCheckbox.setToolTipText(SHOW_FILENAME_TOOLTIP);
		panel.add(showFilenameCheckbox);

		GDLabel useHexLabel = new GDLabel(USE_HEX_LABEL, SwingConstants.RIGHT);
		useHexLabel.setToolTipText(USE_HEX_TOOLTIP);
		panel.add(useHexLabel);
		useHexCheckbox = new GCheckBox();
		useHexCheckbox.setToolTipText(USE_HEX_TOOLTIP);
		panel.add(useHexCheckbox);

		showFilenameCheckbox.addItemListener(evt -> firePropertyChange());
		useHexCheckbox.addItemListener(evt -> firePropertyChange());

		return panel;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof FileOffsetFieldOptionsWrappedOption)) {
			return;
		}

		option = (FileOffsetFieldOptionsWrappedOption) value;
		setLocalValues(option);
		firePropertyChange();
	}

	private void setLocalValues(FileOffsetFieldOptionsWrappedOption option) {
		if (option.showFilename() != showFilenameCheckbox.isSelected()) {
			showFilenameCheckbox.setSelected(option.showFilename());
		}
		if (option.useHex() != useHexCheckbox.isSelected()) {
			useHexCheckbox.setSelected(option.useHex());
		}
	}

	private FileOffsetFieldOptionsWrappedOption cloneFileOffsetValues() {
		FileOffsetFieldOptionsWrappedOption newOption = new FileOffsetFieldOptionsWrappedOption();
		newOption.setShowFilename(showFilenameCheckbox.isSelected());
		newOption.setUseHex(useHexCheckbox.isSelected());
		return newOption;
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
	public Object getValue() {
		return cloneFileOffsetValues();
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}
}
