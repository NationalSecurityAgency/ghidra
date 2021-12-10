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
package ghidra.app.plugin.core.debug.gui.listing;

import ghidra.app.plugin.core.debug.gui.colors.DebuggerTrackedRegisterBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingBackgroundColorModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.Plugin;

public abstract class DebuggerTrackedRegisterListingBackgroundColorModel
		extends DebuggerTrackedRegisterBackgroundColorModel implements ListingBackgroundColorModel {

	public DebuggerTrackedRegisterListingBackgroundColorModel(Plugin plugin,
			ListingPanel listingPanel) {
		super(plugin);
		modelDataChanged(listingPanel);
	}

	@Override
	public void modelDataChanged(ListingPanel listingPanel) {
		this.program = listingPanel == null ? null : listingPanel.getProgram();
		this.addressIndexMap = listingPanel == null ? null : listingPanel.getAddressIndexMap();
	}
}
