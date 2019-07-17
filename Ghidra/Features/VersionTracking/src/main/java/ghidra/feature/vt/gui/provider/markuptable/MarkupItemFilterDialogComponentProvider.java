/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.gui.filters.AncillaryFilterDialogComponentProvider;
import ghidra.feature.vt.gui.filters.FilterDialogModel;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.util.HelpLocation;

import javax.swing.*;

public class MarkupItemFilterDialogComponentProvider extends
		AncillaryFilterDialogComponentProvider<VTMarkupItem> {

	MarkupItemFilterDialogComponentProvider(VTController controller,
			FilterDialogModel<VTMarkupItem> dialogModel) {
		super(controller, "Markup Item Table Filters", dialogModel);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Markup_Filters"));
	}

	@Override
	protected JComponent buildFilterPanel() {
		JPanel rowOnePanel = new JPanel();
		rowOnePanel.setLayout(new BoxLayout(rowOnePanel, BoxLayout.X_AXIS));

		// 
		// row one
		//     

		// status filter
		MarkupStatusFilter statusFilter = new MarkupStatusFilter();
		addFilter(statusFilter);
		rowOnePanel.add(statusFilter.getComponent());

		// markup type
		MarkupTypeFilter typeFilter = new MarkupTypeFilter();
		addFilter(typeFilter);
		rowOnePanel.add(typeFilter.getComponent());

		// These are currently handled by the text field filter on the provider
		// source value        
		// destination value

		return rowOnePanel;
	}
}
