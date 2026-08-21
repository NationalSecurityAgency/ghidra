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
package ghidra.app.plugin.core.byteviewer;

import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.border.Border;

import docking.DialogComponentProvider;
import docking.widgets.button.BrowseButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.fieldpanel.support.ViewerPosition;
import docking.widgets.label.GLabel;
import docking.widgets.spinner.IntegerSpinner;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.plugin.core.format.DataFormatModel;
import ghidra.util.HelpLocation;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.charset.picker.CharsetPickerDialog;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

public class ByteViewerOptionsDialog extends DialogComponentProvider {

	private JTextField charsetField;
	private BrowseButton charsetPickerButton;
	private ByteViewerComponentProvider provider;
	private ByteViewerConfigOptions configOptions;
	private Map<String, JCheckBox> checkboxMap = new HashMap<>();
	private MySpinnerNumberModel bytesPerLineSpinnerModel;
	private MySpinnerNumberModel offsetSpinnerModel;
	private MySpinnerNumberModel hexGroupSizeSpinnerModel;
	private IntegerSpinner bytesPerLineSpinner;
	private IntegerSpinner offsetSpinner;
	private IntegerSpinner hexGroupSizeSpinner;
	private LinkedHashMap<String, DataFormatModel> models = new LinkedHashMap<>();

	public ByteViewerOptionsDialog(ByteViewerComponentProvider provider) {
		super("Byte Viewer Options");
		this.provider = provider;
		this.configOptions = provider.getConfigOptions().clone();

		for (String modelName : provider.getDataFormatNames()) {
			models.put(modelName, provider.getDataFormatModel(modelName));
		}

		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
		setResizable(false);
		setHelpLocation(new HelpLocation("ByteViewerPlugin", "Byte_Viewer_Options"));
		setRememberLocation(false);
		setRememberSize(false);
	}

	private void disposeModels() {
		for (DataFormatModel model : models.values()) {
			model.dispose();
		}
		models.clear();
	}

	private JComponent buildPanel() {
		JPanel mainPanel = new JPanel(new VerticalLayout(10));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		mainPanel.add(buildSettingsPanel());
		mainPanel.add(buildModelPickerPanel());
		updateButtonEnablement();
		return mainPanel;
	}

	private void setTooltip(IntegerSpinner spinner, String text) {
		spinner.getTextField().getComponent().setToolTipText(text);
		spinner.getSpinner().setToolTipText(text);
	}

	private void updateModelStatus(DataFormatModel model, String errorMsg) {
		JCheckBox cb = checkboxMap.get(model.getName());
		if (cb != null) {
			cb.setForeground(errorMsg == null ? Colors.FOREGROUND : Messages.ERROR);
			cb.setToolTipText(errorMsg);
		}
	}

	private boolean isModelEnabled(DataFormatModel model) {
		JCheckBox cb = checkboxMap.get(model.getName());
		return cb != null && cb.isSelected();
	}

	private void updateButtonEnablement() {
		int enabledModelCount = 0;
		String firstErrorMsg = null;
		for (DataFormatModel model : models.values()) {
			String errorMsg = model.validateByteViewerConfigOptions(configOptions);
			if (errorMsg == null &&
				configOptions.getBytesPerLine() % model.getUnitByteSize() != 0) {
				errorMsg = "%s (%d bytes) is not a multiple of %d".formatted(model.getName(),
					model.getUnitByteSize(), configOptions.getBytesPerLine());
			}
			updateModelStatus(model, errorMsg);
			if (isModelEnabled(model)) {
				enabledModelCount++;
				if (errorMsg != null) {
					firstErrorMsg = firstErrorMsg == null ? errorMsg : firstErrorMsg;
				}
			}
		}
		if (enabledModelCount == 0) {
			firstErrorMsg = "You must have at least one view selected";
		}

		setStatusText(firstErrorMsg);
		setOkEnabled(firstErrorMsg == null);
	}

	private Component buildSettingsPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		bytesPerLineSpinnerModel =
			new MySpinnerNumberModel(configOptions.getBytesPerLine(), 1, 256, 1);
		offsetSpinnerModel = new MySpinnerNumberModel(configOptions.getOffset(), 0,
			configOptions.getBytesPerLine() - 1, 1) {
			// wrap around the top and bottom of the valid range
			@Override
			public Object getNextValue() {
				Long val = (Long) getNumber();
				Long maximum = (Long) getMaximum();
				if (maximum != null && maximum.compareTo(val) <= 0) {
					return getMinimum();
				}
				return super.getNextValue();
			}

			@Override
			public Object getPreviousValue() {
				Long val = (Long) getNumber();
				Long min = (Long) getMinimum();
				if (min != null && min.compareTo(val) >= 0) {
					return getMaximum();
				}
				return super.getPreviousValue();
			}
		};
		hexGroupSizeSpinnerModel = new MySpinnerNumberModel(configOptions.getHexGroupSize(), 1,
			configOptions.getBytesPerLine(), 1);

		bytesPerLineSpinner = new MyIntegerSpinner(bytesPerLineSpinnerModel, 3);
		bytesPerLineSpinner.getTextField().setShowNumberMode(false);
		bytesPerLineSpinner.getTextField().setAccessibleName("Bytes Per Line");
		setTooltip(bytesPerLineSpinner, "Number of bytes to display in each row of the viewer.");

		offsetSpinner = new MyIntegerSpinner(offsetSpinnerModel, 3);
		offsetSpinner.getTextField().setShowNumberMode(false);
		offsetSpinner.getTextField().setAccessibleName("Offset");
		setTooltip(offsetSpinner, "Adjusts the starting byte of the row left or right.\n" +
			"Ranges from 0 to bytes per line (exclusive).");

		hexGroupSizeSpinner = new MyIntegerSpinner(hexGroupSizeSpinnerModel, 3);
		hexGroupSizeSpinner.getTextField().setShowNumberMode(false);
		hexGroupSizeSpinner.getTextField().setAccessibleName("Hex Group Size");
		setTooltip(hexGroupSizeSpinner,
			"How many bytes will be grouped together in the hex view.\n" +
				"Ranges from 1 to bytes per line (inclusive).");

		bytesPerLineSpinnerModel.addChangeListener(e -> {
			Long bpl = (Long) bytesPerLineSpinnerModel.getNumber();
			if (bpl != null) {
				setBytesPerLine(bpl.intValue());
			}
		});

		offsetSpinnerModel.addChangeListener(e -> {
			Long val = (Long) offsetSpinnerModel.getNumber();
			if (val != null) {
				setOffset(val.intValue());
			}
		});

		hexGroupSizeSpinnerModel.addChangeListener(e -> {
			Long val = (Long) hexGroupSizeSpinnerModel.getNumber();
			if (val != null) {
				setHexGroupSize(val.intValue());
			}
		});

		panel.add(new GLabel("Bytes Per Line:"));
		panel.add(bytesPerLineSpinner.getSpinner());

		panel.add(new GLabel("Alignment Offset:"));
		panel.add(offsetSpinner.getSpinner());

		panel.add(new GLabel("Hex Group Size:"));
		panel.add(hexGroupSizeSpinner.getSpinner());

		panel.add(new GLabel("Charset:"));
		charsetField = new JTextField();
		charsetField.setEditable(false);
		charsetField.setText(configOptions.getCharsetInfo().getName());
		charsetField.getAccessibleContext().setAccessibleName("Character Set Name");

		charsetPickerButton = new BrowseButton();
		charsetPickerButton.addActionListener(e -> pickCharset());
		charsetPickerButton.getAccessibleContext().setAccessibleName("Character Set Picker");
		JPanel charsetPanel = new JPanel(new BorderLayout());
		charsetPanel.add(charsetField, BorderLayout.CENTER);
		charsetPanel.add(charsetPickerButton, BorderLayout.EAST);
		panel.add(charsetPanel);

		panel.add(new GLabel("Compact Char Width:"));
		GCheckBox compactChars = new GCheckBox();
		compactChars.setSelected(configOptions.isCompactChars());
		compactChars.addChangeListener(e -> {
			configOptions.setCompactChars(compactChars.isSelected());
			// doesn't affect ok enablement, no need to call updateButtonEnablement()
		});
		compactChars.getAccessibleContext().setAccessibleName("Compact Characters");
		compactChars.setToolTipText(
			"Display characters tightly packed together or more widely spaced apart");
		panel.add(compactChars);

		panel.add(new GLabel("Use Char Alignment:"));
		GCheckBox useCharAlignment = new GCheckBox();
		useCharAlignment.setSelected(configOptions.isUseCharAlignment());
		useCharAlignment.addChangeListener(e -> {
			configOptions.setUseCharAlignment(useCharAlignment.isSelected());
			// doesn't affect ok enablement, no need to call updateButtonEnablement()
		});
		useCharAlignment.getAccessibleContext().setAccessibleName("Character Alignment");
		useCharAlignment
				.setToolTipText("Align start-of-character location with charset's byte width.\n" +
					"Only some charsets (like UTF-16/UTF-32) are marked as alignable.");
		panel.add(useCharAlignment);

		return panel;
	}

	void setBytesPerLine(int bpl) {
		configOptions.setBytesPerLine(bpl);
		if (configOptions.getOffset() != offsetSpinnerModel.getNumber().intValue()) {
			offsetSpinnerModel.setValue(Long.valueOf(configOptions.getOffset()));
		}
		if (configOptions.getHexGroupSize() != hexGroupSizeSpinnerModel.getIntValue()) {
			hexGroupSizeSpinnerModel.setValue(Long.valueOf(configOptions.getHexGroupSize()));
		}
		offsetSpinnerModel.setMaximum(Long.valueOf(bpl - 1));
		hexGroupSizeSpinnerModel.setMaximum(Long.valueOf(bpl));

		updateButtonEnablement();
	}

	public void setOffset(int val) {
		configOptions.setOffset(val);
		updateButtonEnablement();
	}

	void setHexGroupSize(int val) {
		configOptions.setHexGroupSize(val);
		updateButtonEnablement();
	}

	private void pickCharset() {
		CharsetInfo newCSI = CharsetPickerDialog.pickCharset(configOptions.getCharsetInfo());
		if (newCSI != null) {
			setCharsetInfo(newCSI);
		}
	}

	private void setCharsetInfo(CharsetInfo newCSI) {
		configOptions.setCharsetInfo(newCSI);
		charsetField.setText(newCSI.getName());
	}

	private JPanel buildModelPickerPanel() {
		JPanel panel = new JPanel(new GridLayout(0, 2, 40, 0));
		Border outer = BorderFactory.createTitledBorder("Views");
		Border inner = BorderFactory.createEmptyBorder(5, 15, 5, 15);
		panel.setBorder(BorderFactory.createCompoundBorder(outer, inner));

		Set<String> currentViews = provider.getCurrentViews();
		for (DataFormatModel model : models.values()) {
			String modelName = model.getName();
			GCheckBox cb = new GCheckBox(modelName);
			cb.addChangeListener(e -> updateButtonEnablement());
			checkboxMap.put(modelName, cb);
			if (currentViews.contains(modelName)) {
				cb.setSelected(true);
			}
			panel.add(cb);
		}

		return panel;
	}

	void setModelSelected(String modelName, boolean selected) {
		JCheckBox cb = checkboxMap.get(modelName);
		cb.setSelected(selected);
	}

	@Override
	protected void okCallback() {
		ViewerPosition vp = provider.getByteViewerPanel().getViewerPosition();
		provider.updateConfigOptions(configOptions, getSelectedViewNames());
		provider.getByteViewerPanel().setViewerPosition(vp);
		disposeModels();
		close();
	}

	@Override
	protected void cancelCallback() {
		disposeModels();
		super.cancelCallback();
	}

	private Set<String> getSelectedViewNames() {
		return checkboxMap.entrySet()
				.stream()
				.filter(entry -> entry.getValue().isSelected())
				.map(entry -> entry.getKey())
				.collect(Collectors.toSet());
	}

	private static class MySpinnerNumberModel extends SpinnerNumberModel {

		public MySpinnerNumberModel(int value, int minimum, int maximum, int stepSize) {
			super(Long.valueOf(value), Long.valueOf(minimum), Long.valueOf(maximum),
				Long.valueOf(stepSize));
		}

		public int getIntValue() {
			return ((Long) getValue()).intValue();
		}

		public boolean isValid(Object value) {
			if (value == null || !(value instanceof Long val)) {
				return false;
			}
			Long minimum = (Long) getMinimum();
			Long maximum = (Long) getMaximum();

			if (minimum.compareTo(val) > 0 || maximum.compareTo(val) < 0) {
				return false;
			}

			return true;
		}

		@Override
		public void setValue(Object value) {
			if (isValid(value)) {
				super.setValue(value);
			}
		}
	}

	private static class MyIntegerSpinner extends IntegerSpinner {
		// change color of text field to red if value that the user manually entered conflicts with
		// spinner model, and when the focus leaves the text field, validate the text and replace
		// it with the current model value if invalid
		MyIntegerSpinner(MySpinnerNumberModel spinnerModel, int columns) {
			super(spinnerModel, columns);

			integerTextField.addChangeListener(e -> {
				BigInteger valObj = integerTextField.getValue();
				Long value = valObj != null ? valObj.longValue() : null;
				integerTextField.getComponent()
						.setForeground(
							spinnerModel.isValid(value) ? Colors.FOREGROUND : Messages.ERROR);
			});
			integerTextField.getComponent().addFocusListener(new FocusListener() {
				@Override
				public void focusLost(FocusEvent e) {
					BigInteger valObj = integerTextField.getValue();
					Long value = valObj != null ? valObj.longValue() : null;
					if (!spinnerModel.isValid(value)) {
						integerTextField.setValue(spinnerModel.getIntValue());
					}
				}

				@Override
				public void focusGained(FocusEvent e) {
					// nothing
				}
			});
		}
	}

}
