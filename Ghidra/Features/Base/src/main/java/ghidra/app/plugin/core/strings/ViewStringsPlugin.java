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
package ghidra.app.plugin.core.strings;

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import javax.swing.Icon;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.data.DataSettingsDialog;
import ghidra.app.plugin.core.data.DataTypeSettingsDialog;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

/**
 * Plugin that provides the "Defined Strings" table, where all the currently defined
 * string data in the program is listed.
 * <p>
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Defined String Table",
	description = "Displays all defined strings in the current program.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class ViewStringsPlugin extends ProgramPlugin implements DomainObjectListener {

	private static Icon REFRESH_ICON = Icons.REFRESH_ICON;
	private static Icon REFRESH_NOT_NEEDED_ICON =
		ResourceManager.getDisabledIcon(Icons.REFRESH_ICON, 60);

	private DockingAction refreshAction;
	private SelectionNavigationAction linkNavigationAction;
	private ViewStringsProvider provider;
	private SwingUpdateManager reloadUpdateMgr;

	public ViewStringsPlugin(PluginTool tool) {
		super(tool);
	}

	void doReload() {
		provider.reload();
	}

	@Override
	protected void init() {
		super.init();

		provider = new ViewStringsProvider(this);
		reloadUpdateMgr = new SwingUpdateManager(100, 60000, this::doReload);
		createActions();
	}

	private void createActions() {
		refreshAction = new ActionBuilder("Refresh Strings", getName())
				.toolBarIcon(REFRESH_NOT_NEEDED_ICON)
				.description("<html>Push at any time to refresh the current table of strings.<br>" +
					"This button is highlighted when the data <i>may</i> be stale.<br>")
				.enabledWhen(ac -> getCurrentProgram() != null)
				.onAction(ac -> {
					refreshAction.getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
					reload();
				})
				.helpLocation(new HelpLocation("ViewStringsPlugin", "Refresh"))
				.buildAndInstallLocal(provider);

		tool.addLocalAction(provider, new MakeProgramSelectionAction(this, provider.getTable()));

		linkNavigationAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, linkNavigationAction);

		new ActionBuilder("Data Settings", getName()) // create pop-up menu item "Settings..."
				.withContext(ViewStringsContext.class)
				.popupMenuPath("Settings...")
				.popupMenuGroup("R")
				.helpLocation(new HelpLocation("DataPlugin", "Data_Settings"))
				.sharedKeyBinding()
				.enabledWhen(vsac -> vsac.getCount() > 0)
				.onAction(vsac -> {
					try {
						DataSettingsDialog dialog =
							vsac.getCount() == 1 ? new DataSettingsDialog(vsac.getSelectedData())
									: new DataSettingsDialog(vsac.getProgram(),
										vsac.getProgramSelection());

						tool.showDialog(dialog);
						dialog.dispose();
					}
					catch (CancelledException e) {
						// do nothing
					}
				})
				.buildAndInstallLocal(provider);

		new ActionBuilder("Default Settings", getName()) // create pop-up menu item "Default Settings..."
				.withContext(ViewStringsContext.class)
				.popupMenuPath("Default Settings...")
				.popupMenuGroup("R")
				.helpLocation(new HelpLocation("DataPlugin", "Default_Settings"))
				.sharedKeyBinding()
				.enabledWhen(vsac -> {
					if (vsac.getCount() != 1) {
						return false;
					}
					Data data = vsac.getSelectedData();
					return data != null && data.getDataType().getSettingsDefinitions().length != 0;
				})
				.onAction(vsac -> {
					Data data = vsac.getSelectedData();
					if (data == null) {
						return;
					}
					DataType dt = data.getDataType();
					DataTypeSettingsDialog dialog =
						new DataTypeSettingsDialog(dt, dt.getSettingsDefinitions());
					tool.showDialog(dialog);
					dialog.dispose();
				})
				.buildAndInstallLocal(provider);
	}

	@Override
	public void dispose() {
		reloadUpdateMgr.dispose();
		provider.dispose();
		super.dispose();
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.setProgram(null);
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.setProgram(program);
	}

	@Override
	protected void locationChanged(ProgramLocation loc) {
		if (linkNavigationAction.isSelected() && loc != null) {
			provider.setProgram(loc.getProgram());
			provider.showProgramLocation(loc);
		}
	}

	private void markDataAsStale() {
		provider.getComponent().repaint();
		refreshAction.getToolBarData().setIcon(REFRESH_ICON);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {

		if (ev.contains(RESTORED, MEMORY_BLOCK_MOVED, MEMORY_BLOCK_REMOVED, DATA_TYPE_CHANGED)) {
			markDataAsStale();
			return;
		}

		for (int i = 0; i < ev.numRecords(); ++i) {

			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			Object newValue = doRecord.getNewValue();
			EventType eventType = doRecord.getEventType();
			if (eventType instanceof ProgramEvent type) {
				switch (type) {
					case CODE_REMOVED:
						ProgramChangeRecord pcRec = (ProgramChangeRecord) doRecord;
						provider.remove(pcRec.getStart(), pcRec.getEnd());
						break;
					case CODE_ADDED:
						if (newValue instanceof Data) {
							provider.add((Data) newValue);
						}
						break;
					default:
						//Msg.info(this, "Unhandled event type: " + doRecord.getEventType());
						break;
				}
			}
		}

		if (ev.contains(ProgramEvent.DATA_TYPE_SETTING_CHANGED)) {
			// Unusual code: because the table model goes directly to the settings values
			// during each repaint, we don't need to figure out which row was changed.
			provider.getComponent().repaint();
		}
	}

	private void reload() {
		reloadUpdateMgr.update();
	}
}
