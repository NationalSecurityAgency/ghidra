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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.plugin.core.format.ByteBlockSelection;
import ghidra.app.plugin.core.format.DataFormatModel;
import ghidra.app.util.AddressInput;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

public class ByteViewerOptionsDialog extends DialogComponentProvider
		implements ChangeListener, ActionListener {

	private AddressInput addressInputField;
	private FixedBitSizeValueField bytesPerLineField;
	private FixedBitSizeValueField groupSizeField;
	private ByteViewerComponentProvider provider;
	private Map<String, JCheckBox> checkboxMap = new HashMap<>();

	public ByteViewerOptionsDialog(ByteViewerComponentProvider provider) {
		super("Byte Viewer Options");
		this.provider = provider;
		addWorkPanel(buildPanel());
		addOKButton();
		addCancelButton();
		setResizable(false);
		setHelpLocation(new HelpLocation("ByteViewerPlugin", "Byte_Viewer_Options"));
		setRememberLocation(false);
		setRememberSize(false);
	}

	private JComponent buildPanel() {
		JPanel mainPanel = new JPanel(new VerticalLayout(10));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		mainPanel.add(buildSettingsPanel());
		mainPanel.add(buildViewOptionsPanel());
		setOkEnabled(hasValidFieldValues());
		return mainPanel;
	}

	private Component buildSettingsPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel("Alignment Address:"));

		if (provider instanceof ProgramByteViewerComponentProvider) {
			Program program = ((ProgramByteViewerComponentProvider) provider).getProgram();
			if (program != null) {
				addressInputField = new AddressInput();
				addressInputField.setAddressFactory(program.getAddressFactory());
				addressInputField.showAddressSpaceCombo(false);
				addressInputField.setAddress(getAlignmentAddress());
				panel.add(addressInputField);
				addressInputField.addChangeListener(this);
			}
		}

		panel.add(new GLabel("Bytes Per Line:"));
		bytesPerLineField = new FixedBitSizeValueField(8, false, true);
		bytesPerLineField.setFormat(10, false);
		bytesPerLineField.setMinMax(BigInteger.valueOf(1), BigInteger.valueOf(256));
		bytesPerLineField.setValue(BigInteger.valueOf(provider.getBytesPerLine()));
		panel.add(bytesPerLineField);
		bytesPerLineField.addChangeListener(this);

		panel.add(new GLabel("Group size (Hex View Only):"));
		groupSizeField = new FixedBitSizeValueField(8, false, true);
		groupSizeField.setFormat(10, false);
		groupSizeField.setMinMax(BigInteger.valueOf(1), BigInteger.valueOf(256));
		groupSizeField.setValue(BigInteger.valueOf(provider.getGroupSize()));
		panel.add(groupSizeField);
		groupSizeField.addChangeListener(this);

		return panel;
	}

	private Component buildViewOptionsPanel() {
		JPanel panel = new JPanel(new GridLayout(0, 2, 40, 0));
		Border outer = BorderFactory.createTitledBorder("Views");
		Border inner = BorderFactory.createEmptyBorder(5, 15, 5, 15);
		panel.setBorder(BorderFactory.createCompoundBorder(outer, inner));

		Set<String> currentViews = provider.getCurrentViews();
		List<String> dataModelNames = provider.getDataFormatNames();
		for (String formatName : dataModelNames) {
			GCheckBox checkBox = new GCheckBox(formatName);
			checkBox.addActionListener(this);
			checkboxMap.put(formatName, checkBox);
			if (currentViews.contains(formatName)) {
				checkBox.setSelected(true);
			}
			panel.add(checkBox);
		}

		return panel;
	}

	private Address getAlignmentAddress() {
		int bytesPerLine = provider.getBytesPerLine();
		int offset = provider.getOffset();

		Address minAddr =
			((ProgramByteViewerComponentProvider) provider).getProgram().getMinAddress();
		long addressOffset = minAddr.getOffset() + offset;

		int alignment = (int) (addressOffset % bytesPerLine);

		return (alignment == 0) ? minAddr : minAddr.add(bytesPerLine - alignment);
	}

	@Override
	protected void okCallback() {
		Address alignmentAddress = addressInputField.getAddress();
		int bytesPerLine = bytesPerLineField.getValue().intValue();
		int groupSize = groupSizeField.getValue().intValue();
		int addrOffset = (int) (alignmentAddress.getOffset() % bytesPerLine);
		// since we want the alignment address to begin a column, need to subtract addrOffset from bytesPerLine
		int offset = addrOffset == 0 ? 0 : bytesPerLine - addrOffset;

		ByteBlockSelection blockSelection = provider.getBlockSelection();

		// Setting these properties individually is problematic since it can temporarily put
		// the system into a bad state.  As a hack, set the bytes per line to 256 since that
		// can support all allowed group sizes.  Then set the group first since there
		// will be a divide by zero exception if the group size is ever bigger than the bytes
		// per line. Also, remove any deleted views before changing settings because the new settings
		// may not be compatible with a deleted view.  Finally, after all setting have been updated,
		// add in the newly added views. This has to happen last because the new views may not be
		// compatible with the old settings.
		removeDeletedViews();
		provider.setBytesPerLine(256);
		provider.setGroupSize(groupSize);
		provider.setBytesPerLine(bytesPerLine);
		provider.setBlockOffset(offset);
		addNewViews();

		close();
	}

	private void removeDeletedViews() {
		Set<String> currentViews = provider.getCurrentViews();

		for (String viewName : currentViews) {
			JCheckBox checkBox = checkboxMap.get(viewName);
			if (!checkBox.isSelected()) {
				provider.removeView(viewName, true);
			}
		}
	}

	private void addNewViews() {
		Set<String> currentViews = provider.getCurrentViews();

		// now add any views that have been selected
		for (String viewName : checkboxMap.keySet()) {
			JCheckBox checkBox = checkboxMap.get(viewName);
			if (!currentViews.contains(viewName) && checkBox.isSelected()) {
				provider.addView(viewName);
			}
		}

	}

	@Override
	public void actionPerformed(ActionEvent e) {
		update();
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		update();
	}

	private void update() {
		setOkEnabled(hasValidFieldValues());
	}

	private boolean hasValidFieldValues() {
		if (addressInputField.getValue().length() == 0) {
			setStatusText("Enter an alignment address");
			return false;
		}
		Address alignmentAddress = addressInputField.getAddress();
		if (alignmentAddress == null) {
			setStatusText("Invalid alignment address:" + addressInputField.getValue());
			return false;
		}
		BigInteger bytesPerLine = bytesPerLineField.getValue();
		if (bytesPerLine == null) {
			setStatusText("Enter a value for Bytes Per Line");
			return false;
		}

		BigInteger groupSize = groupSizeField.getValue();
		if (groupSize == null) {
			setStatusText("Enter a group size");
			return false;
		}
		if (bytesPerLine.intValue() % groupSize.intValue() != 0) {
			setStatusText("The bytes per line must be a multiple of the group size.");
			return false;
		}

		if (checkForUnsupportedModels(bytesPerLine.intValue())) {
			setStatusText("Not all selected views support the current bytes per line value.");
			return false;
		}

		if (!atLeastOneViewOn()) {
			setStatusText("You must have at least one view selected");
			return false;
		}

		setStatusText("");
		return true;
	}

	private boolean atLeastOneViewOn() {
		Set<Entry<String, JCheckBox>> entrySet = checkboxMap.entrySet();
		for (Entry<String, JCheckBox> entry : entrySet) {
			JCheckBox checkBox = entry.getValue();
			if (checkBox.isSelected()) {
				return true;
			}
		}
		return false;
	}

	private boolean checkForUnsupportedModels(int bytesPerLine) {
		boolean isBad = false;
		Set<Entry<String, JCheckBox>> entrySet = checkboxMap.entrySet();
		for (Entry<String, JCheckBox> entry : entrySet) {
			JCheckBox checkBox = entry.getValue();
			DataFormatModel model = provider.getDataFormatModel(entry.getKey());
			if (model.validateBytesPerLine(bytesPerLine)) {
				checkBox.setForeground(Color.BLACK);
			}
			else {
				checkBox.setForeground(Color.RED);
				isBad |= checkBox.isSelected();
			}
		}
		return isBad;
	}
}
