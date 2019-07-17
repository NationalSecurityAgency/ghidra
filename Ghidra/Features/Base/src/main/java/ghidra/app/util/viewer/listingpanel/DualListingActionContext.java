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
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

// Note: If you want to get the typical actions for things like comments, labels, bookmarks, etc.
//       that are available in the CodeBrowser then change this to extend ListingActionContext.
//       This currently extends NavigatableActionContext so that it does NOT get the typical 
//       CodeBrowser Listing actions.
/**
 * Action context for a ListingCodeComparisonPanel.
 */
public class DualListingActionContext extends NavigatableActionContext
		implements CodeComparisonPanelActionContext {

	private CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel = null;

	/**
	 * Constructor for a dual listing's action context.
	 * @param provider the provider that uses this action context.
	 * @param navigatable the navigatable for this action context.
	 * @param program the program in the listing providing this context.
	 * @param location the location indicated by this context.
	 * @param selection the listing selection for this context.
	 * @param highlight the listing highlight for this context.
	 */
	public DualListingActionContext(ComponentProvider provider, Navigatable navigatable,
			Program program, ProgramLocation location, ProgramSelection selection,
			ProgramSelection highlight) {
		super(provider, navigatable, program, location, selection, highlight);
	}

	/**
	 * Constructor for a dual listing's action context.
	 * @param provider the provider that uses this action context.
	 * @param navigatable the navigatable for this action context.
	 * @param location the location indicated by this context.
	 */
	public DualListingActionContext(ComponentProvider provider, Navigatable navigatable,
			ProgramLocation location) {
		super(provider, navigatable, location);
	}

	/**
	 * Constructor for a dual listing's action context.
	 * @param provider the provider that uses this action context.
	 * @param navigatable the navigatable for this action context.
	 */
	public DualListingActionContext(ComponentProvider provider, Navigatable navigatable) {
		super(provider, navigatable);
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
}
