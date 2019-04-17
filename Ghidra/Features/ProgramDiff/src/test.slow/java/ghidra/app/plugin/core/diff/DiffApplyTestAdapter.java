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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.*;

import org.junit.Assert;

import docking.action.DockingActionIf;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramSelection;

public class DiffApplyTestAdapter extends DiffTestAdapter {
	DockingActionIf ignoreAll;
	DockingActionIf replaceAll;
	DockingActionIf mergeAll;

	JComponent settingsPanel;
	JComboBox<?> programContextApplyCB;
	JComboBox<?> byteApplyCB;
	JComboBox<?> codeUnitApplyCB;
	JComboBox<?> refApplyCB;
	JComboBox<?> plateCommentApplyCB;
	JComboBox<?> preCommentApplyCB;
	JComboBox<?> eolCommentApplyCB;
	JComboBox<?> repeatableCommentApplyCB;
	JComboBox<?> postCommentApplyCB;
	JComboBox<?> labelApplyCB;
	JComboBox<?> functionApplyCB;
	JComboBox<?> bookmarkApplyCB;
	JComboBox<?> propertiesApplyCB;
	JComboBox<?> functionTagApplyCB;

	public DiffApplyTestAdapter() {
		super();
	}

	/**
	 * Sets the indicated combo box selection to "Ignore".
	 * @param comboBox the combo box
	 */
	void ignore(final JComboBox<?> comboBox) {
		runSwing(() -> {
			ComboBoxModel<?> model = comboBox.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				if (model.getElementAt(i).toString().equals("Ignore")) {
					comboBox.setSelectedIndex(i);
					break;
				}
			}
			isIgnore(comboBox);
		});
	}

	/**
	 * Sets the indicated combo box selection to "Replace".
	 * @param comboBox the combo box
	 */
	void replace(final JComboBox<?> comboBox) {
		runSwing(() -> {
			ComboBoxModel<?> model = comboBox.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				if (model.getElementAt(i).toString().equals("Replace")) {
					comboBox.setSelectedIndex(i);
					break;
				}
			}
			isReplace(comboBox);
		});
	}

	/**
	 * Sets the indicated combo box selection to "Merge".
	 * @param comboBox the combo box
	 */
	void merge(final JComboBox<?> comboBox) {
		runSwing(() -> {
			ComboBoxModel<?> model = comboBox.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				if (model.getElementAt(i).toString().equals("Merge")) {
					comboBox.setSelectedIndex(i);
					break;
				}
			}
			isMerge(comboBox);
		});
	}

	/**
	 * Sets the indicated combo box selection to "Merge & Set Primary".
	 * @param comboBox the combo box
	 */
	void mergeSetPrimary(final JComboBox<?> comboBox) {
		runSwing(() -> {
			ComboBoxModel<?> model = comboBox.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				if (model.getElementAt(i).toString().equals("Merge & Set Primary")) {
					comboBox.setSelectedIndex(i);
					break;
				}
			}
			isMergeSetPrimary(comboBox);
		});
	}

	/**
	 * @param comboBox the ComboBox for the Diff Apply Setting to check
	 */
	void isIgnore(JComboBox<?> comboBox) {
		assertEquals(comboBox.getName(), "Ignore", comboBox.getSelectedItem().toString());
	}

	/**
	 * @param comboBox the ComboBox for the Diff Apply Setting to check
	 */
	void isReplace(JComboBox<?> comboBox) {
		assertEquals(comboBox.getName(), "Replace", comboBox.getSelectedItem().toString());
	}

	/**
	 * @param comboBox the ComboBox for the Diff Apply Setting to check
	 */
	void isMerge(JComboBox<?> comboBox) {
		assertEquals(comboBox.getName(), "Merge", comboBox.getSelectedItem().toString());
	}

	/**
	 * @param comboBox the ComboBox for the Diff Apply Setting to check
	 */
	void isMergeSetPrimary(JComboBox<?> comboBox) {
		assertEquals(comboBox.getName(), "Merge & Set Primary",
			comboBox.getSelectedItem().toString());
	}

	void waitForApply() {
		waitForCondition(() -> getWindow("Apply Differences") == null);
	}

	void waitForIgnore() {
		waitForCondition(() -> getWindow("Ignore Differences") == null);
	}

	void apply() {
		invokeLater(applyDiffs);
		waitForSwing();
		waitForApply();
		waitForSwing();
	}

	void applyAndNext() {
		invokeLater(applyDiffsNext);
		waitForSwing();
		waitForApply();
		waitForSwing();
	}

	void ignoreAndNext() {
		invokeLater(ignoreDiffs);
		waitForSwing();
		waitForIgnore();
		waitForSwing();
	}

	void showApplySettings() {
		invokeLater(diffApplySettings);
		assertTrue(isProviderShown(tool.getToolFrame(), "Diff Apply Settings"));
		settingsPanel =
			(JComponent) findComponentByName(tool.getToolFrame(), "Diff Apply Settings Panel");
		assertNotNull(settingsPanel);

		getApplySettingsActions();
		getApplySettingsComboBoxes();
	}

	void getApplySettingsActions() {
		ignoreAll = getAction(diffPlugin, "Set All To Ignore");
		replaceAll = getAction(diffPlugin, "Set All To Replace");
		mergeAll = getAction(diffPlugin, "Set All To Merge");
	}

	void getApplySettingsComboBoxes() {
		programContextApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Program Context Diff Apply CB");
		byteApplyCB = (JComboBox<?>) findComponentByName(settingsPanel, "Bytes Diff Apply CB");
		codeUnitApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Code Units Diff Apply CB");
		refApplyCB = (JComboBox<?>) findComponentByName(settingsPanel, "References Diff Apply CB");
		plateCommentApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Plate Comments Diff Apply CB");
		preCommentApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Pre Comments Diff Apply CB");
		eolCommentApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Eol Comments Diff Apply CB");
		repeatableCommentApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Repeatable Comments Diff Apply CB");
		postCommentApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Post Comments Diff Apply CB");
		labelApplyCB = (JComboBox<?>) findComponentByName(settingsPanel, "Labels Diff Apply CB");
		functionApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Functions Diff Apply CB");
		bookmarkApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Bookmarks Diff Apply CB");
		propertiesApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Properties Diff Apply CB");
		functionTagApplyCB =
			(JComboBox<?>) findComponentByName(settingsPanel, "Function Tags Diff Apply CB");
	}

	void checkDiffSelection(AddressSetView addrSet) {
		ProgramSelection expectedSelection = new ProgramSelection(addrSet);
		ProgramSelection currentSelection = cb.getCurrentSelection();
		AddressSet missingFromSelection = expectedSelection.subtract(currentSelection);
		AddressSet unexpectedlySelected = currentSelection.subtract(expectedSelection);
		StringBuffer buf = new StringBuffer();
		if (!missingFromSelection.isEmpty()) {
			buf.append("\nSelection expected the following addresses but they are missing: \n" +
				missingFromSelection.toString());
		}
		if (!unexpectedlySelected.isEmpty()) {
			buf.append("\nSelection unexpectedly contains the following addresses: \n" +
				unexpectedlySelected.toString());
		}
		if (buf.length() > 0) {
			String message = buf.toString();
			Assert.fail(message);
		}
		assertEquals(expectedSelection, currentSelection);
	}

	@SuppressWarnings("unused")
	private void checkAddressArrays(String type, Address[] expectedAddresses,
			Address[] actualAddresses) {
		Arrays.sort(expectedAddresses);
		Arrays.sort(actualAddresses);
		ArrayList<Address> extraList = new ArrayList<>();
		ArrayList<Address> missingList = new ArrayList<>();
		int expectedIndex = 0, actualIndex = 0;
		int expectedLength = expectedAddresses.length;
		int actualLength = actualAddresses.length;
		while ((expectedIndex < expectedLength) && (actualIndex < actualLength)) {
			Address expectedAddress = expectedAddresses[expectedIndex];
			Address actualAddress = actualAddresses[actualIndex];
			int compareExpectedToActual = expectedAddress.compareTo(actualAddress);
			if (compareExpectedToActual == 0) {
				expectedIndex++;
				actualIndex++;
			}
			else if (compareExpectedToActual < 0) {
				missingList.add(expectedAddress);
				expectedIndex++;
			}
			else {
				extraList.add(actualAddress);
				actualIndex++;
			}
		}
		while (expectedIndex < expectedLength) {
			missingList.add(expectedAddresses[expectedIndex]);
			expectedIndex++;
		}
		while (actualIndex < actualLength) {
			extraList.add(actualAddresses[actualIndex]);
			actualIndex++;
		}
		StringBuffer buf = new StringBuffer();
		if (!missingList.isEmpty()) {
			buf.append(type + "s are missing at ");
			buf.append(missingList.get(0).toString());
			int numMissing = missingList.size();
			for (int index = 1; index < numMissing; index++) {
				buf.append(", " + missingList.get(index).toString());
			}
			buf.append(".\n");
		}
		if (!extraList.isEmpty()) {
			buf.append("Unexpectedly found " + type + "s at ");
			buf.append(extraList.get(0).toString());
			int numMissing = extraList.size();
			for (int index = 1; index < numMissing; index++) {
				buf.append(", " + extraList.get(index).toString());
			}
			buf.append(".\n");
		}
		if (buf.length() > 0) {
			String message = buf.toString();
//			System.out.println(message);
			Assert.fail(message);
		}
	}

	void checkProgramSelection(AddressSetView addrSet) {
		assertEquals(new ProgramSelection(addrSet), cb.getCurrentSelection());
	}

	@Override
	void setDiffSelection(final AddressSetView addrSet) {
		runSwing(() -> diffPlugin.setProgram2Selection(new ProgramSelection(addrSet)), true);
	}

}
