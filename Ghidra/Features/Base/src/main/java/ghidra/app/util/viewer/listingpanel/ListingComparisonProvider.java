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

import javax.swing.Icon;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

/**
 * Provider for displaying a ListingCodeComparisonPanel.
 */
public class ListingComparisonProvider extends ComponentProviderAdapter {

	private static final Icon DUAL_LISTING_ICON =
		ResourceManager.loadImage("images/table_relationship.png");
	private ListingCodeComparisonPanel dualListingPanel;

	/**
	 * Constructor for a provider that can display a ListingCodeComparisonPanel.
	 * @param tool the tool that contains this provider.
	 * @param name the owner of this provider, which is usually a plugin name.
	 * @param p1 program for the listing displayed in the left side of the panel.
	 * @param p2 program for the listing displayed in the right side of the panel.
	 * @param set1 the address set indicating the portion of the listing displayed in the left side 
	 * of the panel.
	 * @param set2 the address set indicating the portion of the listing displayed in the right side 
	 * of the panel.
	 */
	public ListingComparisonProvider(PluginTool tool, String name, Program p1, Program p2,
			AddressSetView set1, AddressSetView set2) {
		super(tool, "Listing Comparison", name);
		setIcon(DUAL_LISTING_ICON);
		dualListingPanel = new ListingCodeComparisonPanel(name, tool);
		dualListingPanel.loadAddresses(p1, p2, set1, set2);
		setTransient();
		tool.addComponentProvider(this, true);
	}

	@Override
	public ListingCodeComparisonPanel getComponent() {
		return dualListingPanel;
	}

}
