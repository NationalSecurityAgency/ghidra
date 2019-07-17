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
package ghidra.app.plugin.core.string.translate;

import static ghidra.program.model.data.TranslationSettingsDefinition.TRANSLATION;

import java.util.List;

import docking.action.MenuData;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramTask;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Action for toggling whether or not to display translated strings or the original string.
 */
public class ToggleShowTranslationAction extends AbstractTranslateAction {
	private static final MenuData CODE_VIEWER_MENU_DATA = new MenuData(
		new String[] { "Data", "Translate", "Toggle show translation value" }, META_GROUP);
	private static final MenuData DATA_LIST_MENU_DATA =
		new MenuData(new String[] { "Translate", "Toggle show translation value" }, META_GROUP);

	public ToggleShowTranslationAction(String owner) {
		super("Toggle Show Translated Value", owner, CODE_VIEWER_MENU_DATA, DATA_LIST_MENU_DATA);
		setPopupMenuData(CODE_VIEWER_MENU_DATA);
		setHelpLocation(new HelpLocation(owner, "Toggle_Show_Translated_Value_Menuitem"));
	}

	@Override
	public void actionPerformed(Program program, List<ProgramLocation> dataLocations) {
		ToggleShowTranslationTask task = new ToggleShowTranslationTask(program, dataLocations);
		TaskLauncher.launch(task);
	}

	private static class ToggleShowTranslationTask extends ProgramTask {
		private List<ProgramLocation> dataLocations;

		protected ToggleShowTranslationTask(Program program, List<ProgramLocation> dataLocations) {
			super(program, "Toggle show translated string", true, true, true);
			this.dataLocations = dataLocations;
		}

		@Override
		protected void doRun(TaskMonitor monitor) {
			monitor.initialize(dataLocations.size());
			for (ProgramLocation progLoc : dataLocations) {
				Data data = DataUtilities.getDataAtLocation(progLoc);
				TRANSLATION.setShowTranslated(data, !TRANSLATION.isShowTranslated(data));
			}
		}
	}
}
