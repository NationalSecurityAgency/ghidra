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
package ghidra.app.plugin.core.datamgr.tree;

import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * Data Types provider dialog to allow users to change the types that are filtered.
 */
public class DtFilterDialog extends DialogComponentProvider {

	private GCheckBox arraysCheckBox = new GCheckBox("Show Arrays");
	private GCheckBox enumsCheckBox = new GCheckBox("Show Enums");
	private GCheckBox functionsCheckBox = new GCheckBox("Show Functions");
	private GCheckBox pointersCheckBox = new GCheckBox("Show Pointers");
	private GCheckBox structuresCheckBox = new GCheckBox("Show Structures");
	private GCheckBox unionsCheckBox = new GCheckBox("Show Unions");

	private DtFilterState filterState;
	private boolean isCancelled;

	public DtFilterDialog(DtFilterState filterState) {
		super("Data Types Filter");
		this.filterState = filterState;

		addWorkPanel(buildWorkPanel());

		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation(HelpTopics.DATA_MANAGER, "Set Filter"));

		initCheckBoxes();
		setRememberSize(false);
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		isCancelled = true;
	}

	@Override
	protected void okCallback() {
		close();
	}

	public boolean isCancelled() {
		return isCancelled;
	}

	public DtFilterState getFilterState() {
		DtFilterState newState = new DtFilterState();

		newState.setShowArrays(arraysCheckBox.isSelected());
		newState.setShowEnums(enumsCheckBox.isSelected());
		newState.setShowFunctions(functionsCheckBox.isSelected());
		newState.setShowPointers(pointersCheckBox.isSelected());
		newState.setShowStructures(structuresCheckBox.isSelected());
		newState.setShowUnions(unionsCheckBox.isSelected());

		return newState;
	}

	private JPanel buildWorkPanel() {

		JPanel panel = new JPanel(new PairLayout(5, 10));

		panel.add(arraysCheckBox);
		panel.add(enumsCheckBox);
		panel.add(functionsCheckBox);
		panel.add(pointersCheckBox);
		panel.add(structuresCheckBox);
		panel.add(unionsCheckBox);

		return panel;
	}

	private void initCheckBoxes() {

		arraysCheckBox.setSelected(filterState.isShowArrays());
		enumsCheckBox.setSelected(filterState.isShowEnums());
		functionsCheckBox.setSelected(filterState.isShowFunctions());
		pointersCheckBox.setSelected(filterState.isShowPointers());
		structuresCheckBox.setSelected(filterState.isShowStructures());
		unionsCheckBox.setSelected(filterState.isShowUnions());
	}

}
