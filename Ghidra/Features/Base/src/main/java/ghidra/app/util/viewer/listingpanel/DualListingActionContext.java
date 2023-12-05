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
package ghidra.app.util.viewer.listingpanel;

import docking.ComponentProvider;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.util.viewer.util.CodeComparisonActionContext;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.program.model.listing.Function;

// Note: If you want to get the typical actions for things like comments, labels, bookmarks, etc.
//       that are available in the CodeBrowser then change this to extend ListingActionContext.
//       This currently extends NavigatableActionContext so that it does NOT get the typical 
//       CodeBrowser Listing actions.
/**
 * Action context for a ListingCodeComparisonPanel.
 */
public class DualListingActionContext extends CodeComparisonActionContext {

	private CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel = null;

	/**
	 * Constructor for a dual listing's action context.
	 * @param provider the provider that uses this action context.
	 */
	public DualListingActionContext(ComponentProvider provider) {
		super(provider);
	}

	/**
	 * Sets the CodeComparisonPanel associated with this context.
	 * @param codeComparisonPanel the code comparison panel
	 */
	public void setCodeComparisonPanel(
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel) {
		this.codeComparisonPanel = codeComparisonPanel;
	}

	@Override
	public CodeComparisonPanel<? extends FieldPanelCoordinator> getCodeComparisonPanel() {
		return codeComparisonPanel;
	}

	@Override
	public Function getSourceFunction() {
		boolean leftHasFocus = codeComparisonPanel.leftPanelHasFocus();

		return leftHasFocus ? codeComparisonPanel.getRightFunction()
				: codeComparisonPanel.getLeftFunction();
	}

	@Override
	public Function getTargetFunction() {
		boolean leftHasFocus = codeComparisonPanel.leftPanelHasFocus();

		return leftHasFocus ? codeComparisonPanel.getLeftFunction()
				: codeComparisonPanel.getRightFunction();
	}
}
