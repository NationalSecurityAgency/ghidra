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
package ghidra.feature.vt.gui.provider.markuptable;

import java.util.List;

import docking.ActionContext;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;
import ghidra.feature.vt.api.main.VTMarkupItem;

/**
 * Action context for the version tracking markup item provider.
 */
public class VTMarkupItemContext extends ActionContext implements CodeComparisonPanelActionContext {

	private final List<VTMarkupItem> selectedItems;
	private CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel = null;

	/**
	 * Creates an action context for the VT markup item provider.
	 * @param provider the version tracking markup item provider.
	 * @param selectedItems the selected markup items.
	 */
	VTMarkupItemContext(VTMarkupItemsTableProvider provider, List<VTMarkupItem> selectedItems) {
		super(provider, null);
		this.selectedItems = selectedItems;
	}

	/**
	 * Gets the currently selected markup items in the version tracking markup item provider.
	 * @return the selected markup items
	 */
	public List<VTMarkupItem> getSelectedMarkupItems() {
		return selectedItems;
	}

	/**
	 * Sets the CodeComparisonPanel associated with this context.
	 * @param codeComparisonPanel the code comparison panel.
	 */
	public void setCodeComparisonPanel(
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel) {
		this.codeComparisonPanel = codeComparisonPanel;
	}

	@Override
	public CodeComparisonPanel<? extends FieldPanelCoordinator> getCodeComparisonPanel() {
		return codeComparisonPanel;
	}
}
