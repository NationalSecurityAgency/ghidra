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
package ghidra.app.util.datatype;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.data.DataTypeParser;
import ghidra.util.layout.VerticalLayout;

public class ApplyEnumDialog extends DataTypeSelectionDialog {
	private boolean shouldApplyOnSubOps;

	public ApplyEnumDialog(PluginTool pluginTool, DataTypeManager dtm) {
		super(pluginTool, dtm, -1, DataTypeParser.AllowedDataTypes.FIXED_LENGTH);
	}

	@Override
	protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {
		setTitle("Apply Enum");

		JPanel updatedPanel = new JPanel();
		updatedPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 0));
		updatedPanel.setLayout(new VerticalLayout(5));

		JCheckBox subOpCB = new GCheckBox("Apply to sub-operands", shouldApplyOnSubOps);
		subOpCB.setName("subOpCB");
		subOpCB.setToolTipText("Applies this enum to the 'nested scalars'.");
		subOpCB.setBorder(BorderFactory.createEmptyBorder(0, 20, 0, 0));
		subOpCB.addActionListener(evt -> shouldApplyOnSubOps = subOpCB.isSelected());

		GLabel label = new GLabel("Choose an Enum data type to apply.");
		label.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
		updatedPanel.add(label);

		updatedPanel.add(dtEditor.getEditorComponent());
		updatedPanel.add(subOpCB);

		return updatedPanel;
	}

	public boolean shouldApplyOnSubOps() {
		return shouldApplyOnSubOps;
	}
}
