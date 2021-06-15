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

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.data.DataSettingsDialog;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
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
	private DockingAction showSettingsAction;
	private DockingAction showDefaultSettingsAction;
	private SelectionNavigationAction linkNavigationAction;
	private ViewStringsProvider provider;
	private SwingUpdateManager reloadUpdateMgr;

	public ViewStringsPlugin(PluginTool tool) {
		super(tool, false, false);
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
		refreshAction = new DockingAction("Refresh Strings", getName()) {

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return getCurrentProgram() != null;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
				reload();
			}
		};
		refreshAction.setToolBarData(new ToolBarData(REFRESH_NOT_NEEDED_ICON));
		refreshAction.setDescription(
			"<html>Push at any time to refresh the current table of strings.<br>" +
				"This button is highlighted when the data <i>may</i> be stale.<br>");
		refreshAction.setHelpLocation(new HelpLocation("ViewStringsPlugin", "Refresh"));
		tool.addLocalAction(provider, refreshAction);

		tool.addLocalAction(provider, new MakeProgramSelectionAction(this, provider.getTable()));

		linkNavigationAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, linkNavigationAction);

		showSettingsAction = new DockingAction("Settings", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try {
					DataSettingsDialog dialog = provider.getSelectedRowCount() == 1
							? new DataSettingsDialog(currentProgram, provider.getSelectedData())
							: new DataSettingsDialog(currentProgram, provider.selectData());

					tool.showDialog(dialog);
					dialog.dispose();
				}
				catch (CancelledException e) {
					// do nothing
				}
			}

		};
		showSettingsAction.setPopupMenuData(new MenuData(new String[] { "Settings..." }, "R"));
		showSettingsAction.setDescription("Shows settings for the selected strings");
		showSettingsAction.setHelpLocation(new HelpLocation("DataPlugin", "Data_Settings"));
		showDefaultSettingsAction = new DockingAction("Default Settings", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Data data = provider.getSelectedData();
				DataSettingsDialog dataSettingsDialog =
					new DataSettingsDialog(getCurrentProgram(), data.getDataType());
				tool.showDialog(dataSettingsDialog);
				dataSettingsDialog.dispose();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return provider.getSelectedRowCount() == 1;
			}
		};
		showDefaultSettingsAction.setPopupMenuData(
			new MenuData(new String[] { "Default Settings..." }, "R"));
		showDefaultSettingsAction.setDescription(
			"Shows settings for the selected string data type");
		showDefaultSettingsAction.setHelpLocation(
			new HelpLocation("DataPlugin", "Default_Data_Settings"));

		tool.addLocalAction(provider, showSettingsAction);
		tool.addLocalAction(provider, showDefaultSettingsAction);

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

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_CHANGED)) {
			markDataAsStale();
			return;
		}

		for (int i = 0; i < ev.numRecords(); ++i) {

			DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
			Object newValue = doRecord.getNewValue();
			switch (doRecord.getEventType()) {
				case ChangeManager.DOCR_CODE_REMOVED:
					ProgramChangeRecord pcRec = (ProgramChangeRecord) doRecord;
					provider.remove(pcRec.getStart(), pcRec.getEnd());
					break;
				case ChangeManager.DOCR_CODE_ADDED:
					if (newValue instanceof Data) {
						provider.add((Data) newValue);
					}
					break;
				default:
					//Msg.info(this, "Unhandled event type: " + doRecord.getEventType());
					break;
			}
		}

		if (ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED)) {
			// Unusual code: because the table model goes directly to the settings values
			// during each repaint, we don't need to figure out which row was changed.
			provider.getComponent().repaint();
		}
	}

	private void reload() {
		reloadUpdateMgr.update();
	}
}
