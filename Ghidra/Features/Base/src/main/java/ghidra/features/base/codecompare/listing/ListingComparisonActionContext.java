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
package ghidra.features.base.codecompare.listing;

import docking.ComponentProvider;
import ghidra.features.base.codecompare.panel.CodeComparisonActionContext;

/**
 * Action context for a ListingCodeComparisonPanel.
 */
public class ListingComparisonActionContext extends CodeComparisonActionContext {

	private ListingCodeComparisonView codeComparisonPanel = null;

	/**
	 * Constructor for a dual listing's action context.
	 * @param provider the provider that uses this action context.
	 * @param panel the ListingCodeComparisonPanel that generated this context
	 */
	public ListingComparisonActionContext(ComponentProvider provider, ListingCodeComparisonView panel) {
		super(provider, panel, panel.getActiveListingPanel().getFieldPanel());
		this.codeComparisonPanel = panel;
	}

	/**
	 * Returns the {@link ListingCodeComparisonView} that generated this context
	 * @return the listing comparison panel that generated this context
	 */
	@Override
	public ListingCodeComparisonView getCodeComparisonView() {
		return codeComparisonPanel;
	}

}
