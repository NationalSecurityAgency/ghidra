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
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.features.base.codecompare.panel.CodeComparisonView;
import ghidra.features.base.codecompare.panel.CodeComparisonViewActionContext;

/**
 * Action context for a version tracking listing.
 */
public class VTListingContext extends ListingActionContext
		implements CodeComparisonViewActionContext {

	private CodeComparisonView codeComparisonView = null;

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
	 * @param codeComparisonView the code comparison panel.
	 */
	public void setCodeComparisonPanel(CodeComparisonView codeComparisonView) {
		this.codeComparisonView = codeComparisonView;
	}

	@Override
	public CodeComparisonView getCodeComparisonView() {
		return codeComparisonView;
	}
}
