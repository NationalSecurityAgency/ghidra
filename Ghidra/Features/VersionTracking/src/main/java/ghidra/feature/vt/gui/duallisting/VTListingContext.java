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
package ghidra.feature.vt.gui.duallisting;

import docking.ComponentProvider;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;

/**
 * Action context for a version tracking listing.
 */
public class VTListingContext extends ListingActionContext
		implements CodeComparisonPanelActionContext {

	private CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel = null;

	/**
	 * Creates an action context for a VT listing.
	 * @param provider the provider for this context.
	 * @param navigatable the associated navigatable for navigation and selection.
	 */
	public VTListingContext(ComponentProvider provider, Navigatable navigatable) {
		super(provider, navigatable);
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
