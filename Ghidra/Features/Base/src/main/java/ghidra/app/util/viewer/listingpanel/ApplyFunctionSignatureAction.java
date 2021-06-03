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

import docking.ActionContext;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.plugin.core.functioncompare.actions.AbstractApplyFunctionSignatureAction;
import ghidra.app.util.viewer.util.CodeComparisonPanel;

/**
 * Action that applies the signature of the function in the currently active side of a listing
 * code comparison panel to the function in the other side of the panel.
 */
public class ApplyFunctionSignatureAction extends AbstractApplyFunctionSignatureAction {

	/**
	 * Constructor for the action that applies a function signature from one side of a dual
	 * listing panel to the other.
	 * @param owner the owner of this action.
	 */
	public ApplyFunctionSignatureAction(String owner) {
		super(owner);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof DualListingActionContext);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof DualListingActionContext) {
			DualListingActionContext compareContext = (DualListingActionContext) context;
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel =
				compareContext.getCodeComparisonPanel();
			if (codeComparisonPanel instanceof ListingCodeComparisonPanel) {
				return !hasReadOnlyNonFocusedSide(codeComparisonPanel);
			}
		}
		return false;
	}
}
