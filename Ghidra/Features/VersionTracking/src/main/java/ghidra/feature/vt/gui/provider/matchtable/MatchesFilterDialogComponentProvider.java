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
package ghidra.feature.vt.gui.provider.matchtable;

import javax.swing.*;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.filters.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VariableRowHeightGridLayout;
import ghidra.util.layout.VerticalLayout;

public class MatchesFilterDialogComponentProvider extends
		AncillaryFilterDialogComponentProvider<VTMatch> {

	protected MatchesFilterDialogComponentProvider(VTController controller,
			FilterDialogModel<VTMatch> dialogModel) {
		super(controller, "Match Table Filters", dialogModel);

		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Match_Filters"));
	}

	@Override
	protected JComponent buildFilterPanel() {
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		panel.setLayout(new VerticalLayout(0));

		JPanel rowOnePanel = new JPanel(new VariableRowHeightGridLayout(3));
		JPanel rowTwoPanel = new JPanel(new VariableRowHeightGridLayout(0, 0, 2));

		// Row 1 - Left Component
		// status filter
//        MatchStatusFilter statusFilter = new MatchStatusFilter();
//        addFilter( statusFilter );
//        rowOnePanel.add( statusFilter.getComponent() );

		// Row 1 - Middle Component 
		// match type filter
		MatchTypeFilter matchTypeFilter = new MatchTypeFilter();
		addFilter(matchTypeFilter);
		rowOnePanel.add(matchTypeFilter.getComponent());

		// Row 1 - Right Component 
		// association status filter
		AssociationStatusFilter associationStatusFilter = new AssociationStatusFilter();
		addFilter(associationStatusFilter);
		rowOnePanel.add(associationStatusFilter.getComponent());

		// Row 2 - Left Component        
		// symbol type filter
		SymbolTypeFilter symbolTypeFilter = new SymbolTypeFilter();
		addFilter(symbolTypeFilter);
		rowTwoPanel.add(symbolTypeFilter.getComponent());

		// Row 2 - Right Component        
		// algorithm filter
		AlgorithmFilter algorithmFilter = new AlgorithmFilter();
		addFilter(algorithmFilter);
		rowTwoPanel.add(algorithmFilter.getComponent());

		//
		// row three
		//

		// address range filter
		MatchAddressRangeFilter addressRangeFilter = new MatchAddressRangeFilter();
		addFilter(addressRangeFilter);
		// added below
//        addressRangePanel.add( addressRangeFilter.getComponent() );
//        addressRangePanel.add( Box.createHorizontalGlue() );

		//
		// row four
		//
		TagFilter tagFilter = new TagFilter(controller);
		addFilter(tagFilter);
		// added below

// matching address filter

// match count filter

		panel.add(rowOnePanel);
		panel.add(rowTwoPanel);
		panel.add(addressRangeFilter.getComponent());
		panel.add(tagFilter.getComponent());

		return panel;
	}
}
