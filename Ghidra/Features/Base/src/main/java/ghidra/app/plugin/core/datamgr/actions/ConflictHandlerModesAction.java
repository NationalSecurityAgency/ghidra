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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.Icon;

import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import generic.theme.GIcon;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResolutionPolicy;
import ghidra.util.HelpLocation;

public class ConflictHandlerModesAction extends
		MultiStateDockingAction<DataTypeConflictHandler.ConflictResolutionPolicy> {

//	private final DataTypeManagerPlugin plugin;

	public ConflictHandlerModesAction(DataTypeManagerPlugin plugin) {
		super("Data Type Conflict Resolution Mode", plugin.getName());
//		this.plugin = plugin;

		setGroup("conflicts");

		HelpLocation conflictModesHelpLocation =
			new HelpLocation(plugin.getName(), "conflict_mode");
		setHelpLocation(conflictModesHelpLocation);

		//@formatter:off
		Icon renameAndAddIcon = new GIcon("icon.plugin.datatypes.conflict.mode.rename.and.add");
		Icon useExistingIcon = new GIcon("icon.plugin.datatypes.conflict.mode.use.existing");
		Icon replaceExistingIcon = new GIcon("icon.plugin.datatypes.conflict.mode.replace.existing");
		Icon replaceDefaultIcon = new GIcon("icon.plugin.datatypes.conflict.mode.replace.or.rename");
		//@formatter:on

		ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> renameAndAddState =
			new ActionState<>(
				"Rename New or Moved Data Type", renameAndAddIcon,
				DataTypeConflictHandler.ConflictResolutionPolicy.RENAME_AND_ADD);
		renameAndAddState.setHelpLocation(conflictModesHelpLocation);

		ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> useExistingState =
			new ActionState<>(
				"Use Existing Data Type", useExistingIcon,
				DataTypeConflictHandler.ConflictResolutionPolicy.USE_EXISTING);
		useExistingState.setHelpLocation(conflictModesHelpLocation);

		ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> replaceExistingState =
			new ActionState<>(
				"Replace Existing Data Type", replaceExistingIcon,
				DataTypeConflictHandler.ConflictResolutionPolicy.REPLACE_EXISTING);
		replaceExistingState.setHelpLocation(conflictModesHelpLocation);

		ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> replaceDefaultState =
			new ActionState<>(
				"Replace Empty Structures else Rename",
				replaceDefaultIcon,
				DataTypeConflictHandler.ConflictResolutionPolicy.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD);
		replaceDefaultState.setHelpLocation(conflictModesHelpLocation);

		addActionState(renameAndAddState);
		addActionState(useExistingState);
		addActionState(replaceExistingState);
		addActionState(replaceDefaultState);

		setCurrentActionState(renameAndAddState);

		setEnabled(true);
	}

	@Override
	public void actionStateChanged(ActionState<ConflictResolutionPolicy> newActionState,
			EventTrigger trigger) {
		// action tracks its own state
	}

}
