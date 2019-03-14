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
package ghidra.feature.vt.gui.filters;

import java.util.*;
import java.util.Map.Entry;

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import ghidra.feature.vt.gui.filters.Filter.FilterShortcutState;
import ghidra.feature.vt.gui.plugin.VTController;

public abstract class AncillaryFilterDialogComponentProvider<T> extends DialogComponentProvider {

	private FilterChangedListener filterChangedListener;
	private Set<AncillaryFilter<T>> ancillaryFilters = new HashSet<AncillaryFilter<T>>();
	private Map<AncillaryFilter<T>, FilterState> originalState =
		new HashMap<AncillaryFilter<T>, FilterState>();

	protected final VTController controller;
	private final FilterDialogModel<T> dialogModel;

	private Boolean isFiltered;

	protected AncillaryFilterDialogComponentProvider(VTController controller, String title,
			FilterDialogModel<T> dialogModel) {
		super(title, true);
		this.controller = controller;
		this.dialogModel = dialogModel;

		filterChangedListener = state -> stateChanged(state);

		addWorkPanel(buildWorkPanel());
		addApplyButton();
		addOKButton();
		addCancelButton();

		applyButton.setToolTipText("Apply any filter changes");
		okButton.setToolTipText("Apply any filter changes and close the dialog");
		cancelButton.setToolTipText("Undo any changes and close the dialog");

		updateButtons(false);
	}

	/**
	 * Returns true if any of the filters managed by this dialog are not in their default state.
	 */
	public boolean isFiltered() {
		if (isFiltered != null) {
			return isFiltered;
		}

		isFiltered = Boolean.FALSE;
		for (Filter<T> filter : ancillaryFilters) {
			FilterShortcutState state = filter.getFilterShortcutState();
			if (state != FilterShortcutState.ALWAYS_PASSES) {
				isFiltered = Boolean.TRUE;
			}
		}

		return isFiltered;
	}

	@Override
	public void close() {
		super.close();
		originalState.clear();
		dialogModel.dialogVisibilityChanged(false);
		updateButtons(false);
	}

	@Override
	protected void dialogShown() {
		dialogModel.dialogVisibilityChanged(true);
		originalState = getCurrentState();
		isFiltered = null;
	}

	@Override
	protected void cancelCallback() {
		applyState(originalState);
		close();
	}

	@Override
	protected void okCallback() {
		applyState(getCurrentState());
		close();
	}

	@Override
	protected void applyCallback() {
		applyState(getCurrentState());
		updateButtons(false);
		dialogModel.forceRefilter();
		originalState = getCurrentState();
	}

	private void applyState(Map<AncillaryFilter<T>, FilterState> state) {
		for (Entry<AncillaryFilter<T>, FilterState> entry : state.entrySet()) {
			AncillaryFilter<T> filter = entry.getKey();
			FilterState filterState = entry.getValue();
			filter.restoreFilterState(filterState);
		}
	}

	private void stateChanged(FilterState state) {
		// see if we need to update our buttons' enablement		
		boolean hasChanges = hasStateChanged(state);
		updateButtons(hasChanges);
	}

	private void updateButtons(boolean hasChanges) {
		applyButton.setEnabled(hasChanges);
		cancelButton.setEnabled(hasChanges);
	}

	private boolean hasStateChanged(FilterState state) {
		FilterState oldState = originalState.get(state.getFilter());

		if (oldState == null) {
			// this can happen when the user presses escape, as the focus event happens after we
			// close the dialog
			return false;
		}
		return !oldState.equals(state);
	}

	private Map<AncillaryFilter<T>, FilterState> getCurrentState() {
		Map<AncillaryFilter<T>, FilterState> state = new HashMap<AncillaryFilter<T>, FilterState>();
		for (AncillaryFilter<T> filter : ancillaryFilters) {
			state.put(filter, filter.getFilterState());
		}
		return state;
	}

	private JComponent buildWorkPanel() {
		return buildFilterPanel();
	}

	protected abstract JComponent buildFilterPanel();

	protected void addFilter(AncillaryFilter<T> filter) {
		filter.addFilterChangedListener(filterChangedListener);
		ancillaryFilters.add(filter);
		dialogModel.addFilter(filter);
	}
}
