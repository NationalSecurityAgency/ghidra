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
import ghidra.app.util.datatype.DataTypeUrl;
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
	private HistoryList<DataTypeUrl> history;

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
		// rely on the individual actions to navigate, as they know them item that is being
		// navigated to, allowing them to skip through the list
		List<DockingActionIf> actions = getActionList(context);
		DockingActionIf action = actions.get(0);
		action.actionPerformed(context);
		provider.contextChanged();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !getActionList(context).isEmpty();
	}

	@Override
	public List<DockingActionIf> getActionList(ActionContext context) {
		return createNavigationActions();
	}

	private List<DockingActionIf> createNavigationActions() {

		DataTypeManager lastDtm = null;
		List<DockingActionIf> results = new ArrayList<>();
		List<DataTypeUrl> types =
			isNext ? history.getNextHistoryItems() : history.getPreviousHistoryItems();

		for (DataTypeUrl url : types) {

			DataType dt = url.getDataType(provider.getPlugin());
			if (dt == null) {
				// The type may have been removed; maybe an undo happened.  Leave the item in
				// the list in case a redo is performed
				continue;
			}

			DataTypeManager dtm = dt.getDataTypeManager();
			if (dtm != lastDtm && !results.isEmpty()) {
				// add a separator to show the user they are navigating across managers
				results.add(createHorizontalRule(lastDtm, dtm));
			}

			results.add(new NavigationAction(url, dt));
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

		private DataTypeUrl url;

		private NavigationAction(DataTypeUrl url, DataType dt) {
			super("DataTypeNavigationAction_" + ++navigationActionIdCount, owner);
			this.url = url;

			setMenuBarData(new MenuData(new String[] { dt.getDisplayName() }));
			setEnabled(true);
			setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Navigation_Actions"));
		}

		@Override
		public void actionPerformed(ActionContext context) {

			// note: we use 'goBackTo()' and 'goForwardTo()' since items in the history list
			//       may not have been added to the multi-action; we have to tell the list
			//       to skip those items.
			if (isNext) {
				history.goForwardTo(url);
			}
			else {
				history.goBackTo(url);
			}
			provider.contextChanged();
		}
	}
}
