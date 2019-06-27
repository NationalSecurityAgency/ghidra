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
package ghidra.app.plugin.core.datamgr;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import docking.menu.MultiActionDockingAction;
import ghidra.base.actions.HorizontalRuleAction;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.HelpLocation;
import resources.Icons;
import util.HistoryList;

/**
 * An action to navigate backwards or forwards in the history of data types
 */
class NextPreviousDataTypeAction extends MultiActionDockingAction {

	private boolean isNext;
	private String owner;
	private DataTypesProvider provider;
	private HistoryList<DataType> history;

	public NextPreviousDataTypeAction(DataTypesProvider provider, String owner, boolean isNext) {
		super(isNext ? "Next Data Type in History" : "Previous Data Type in History", owner);
		this.owner = owner;
		this.provider = provider;
		this.isNext = isNext;

		Icon icon = null;
		if (isNext) {
			icon = Icons.RIGHT_ALTERNATE_ICON;
		}
		else {
			icon = Icons.LEFT_ALTERNATE_ICON;
		}

		setToolBarData(new ToolBarData(icon, "1_Navigation"));
		setDescription(
			isNext ? "Go to next data type in history" : "Go to previous data type in history");
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Navigation_Actions"));
		setEnabled(false);

		history = provider.getNavigationHistory();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (isNext) {
			history.goForward();
		}
		else {
			history.goBack();
		}
		provider.contextChanged();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		if (isNext) {
			return history.hasNext();
		}
		return history.hasPrevious();
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		return createNavigationActions();
	}

	private List<DockingActionIf> createNavigationActions() {

		DataTypeManager lastDtm = null;
		List<DockingActionIf> results = new ArrayList<>();
		List<DataType> types =
			isNext ? history.getNextHistoryItems() : history.getPreviousHistoryItems();

		for (DataType dt : types) {

			DataTypeManager dtm = dt.getDataTypeManager();

			if (dtm != lastDtm && !results.isEmpty()) {
				// add a separator to show the user they are navigating across managers
				results.add(createHorizontalRule(lastDtm, dtm));
			}

			results.add(new NavigationAction(dt));
			lastDtm = dtm;
		}

		return results;
	}

	private DockingActionIf createHorizontalRule(DataTypeManager lastDtm, DataTypeManager nextDtm) {

		String topName = lastDtm.getName();
		String bottomName = nextDtm.getName();
		return new HorizontalRuleAction(getName(), topName, bottomName);
	}

	private static int navigationActionIdCount = 0;

	private class NavigationAction extends DockingAction {

		private NavigationAction(DataType dt) {
			super("DataTypeNavigationAction_" + ++navigationActionIdCount, owner);

			setMenuBarData(new MenuData(new String[] { dt.getDisplayName() }));
			setEnabled(true);
			setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Navigation_Actions"));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (isNext) {
				history.goForward();
			}
			else {
				history.goBack();
			}
			provider.contextChanged();
		}
	}
}
