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
package ghidra.features.bsim.gui.search.results;

import java.awt.Dimension;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JComponent;

import docking.DialogComponentProvider;
import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.gui.search.dialog.BSimFilterPanel;
import ghidra.features.bsim.gui.search.dialog.BSimFilterSet;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;

/**
 * Dialog for configuring post BSim search filters
 */
public class BSimSearchResultsFilterDialog extends DialogComponentProvider {

	private BSimFilterPanel filterPanel;
	private boolean cancelled = false;

	protected BSimSearchResultsFilterDialog(List<BSimFilterType> filters, BSimFilterSet filterSet) {
		super("BSim Results Filters");
		setTransient(isTransient());

		addWorkPanel(buildMainPanel(filters, filterSet));
		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "BSim_Filters"));
	}

	private JComponent buildMainPanel(List<BSimFilterType> filters, BSimFilterSet filterSet) {
		filterPanel = new BSimFilterPanel(filters, filterSet, this::filterValueChanged);
		filterPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
		filterPanel.setPreferredSize(new Dimension(700, 200));
		return filterPanel;
	}

	private void filterValueChanged() {
		if (filterPanel.hasValidFilters()) {
			setOkEnabled(true);
			clearStatusText();
		}
		else {
			setOkEnabled(false);
			setStatusText("One or more filters has invalid data!", MessageType.ERROR);
		}
	}

	public BSimFilterSet getFilters() {
		if (cancelled) {
			return null;
		}
		return filterPanel.getFilterSet();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	@Override
	protected void okCallback() {
		if (!filterPanel.hasValidFilters()) {
			setStatusText("One or more filters is invalid!", MessageType.ERROR);
			return;
		}
		close();
	}

}
