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
package ghidra.app.plugin.core.datawindow;

import java.util.ArrayList;
import java.util.Iterator;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramTreeService;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays defined data",
	description = "This plugin provides a component for showing all the defined "
			+ "data in the current program.  The data display can be filtered and used "
			+ "for navigation.",
	servicesRequired = { GoToService.class },
	eventsConsumed = { ViewChangedPluginEvent.class }
)
//@formatter:on
public class DataWindowPlugin extends ProgramPlugin implements DomainObjectListener {

	private DockingAction selectAction;
	private FilterAction filterAction;
	private DataWindowProvider provider;

	private SwingUpdateManager resetUpdateMgr;
	private SwingUpdateManager reloadUpdateMgr;
	private boolean resetTypesNeeded;

	public DataWindowPlugin(PluginTool tool) {
		super(tool, true, true);

		resetUpdateMgr = new SwingUpdateManager(100, 60000, () -> doReset());

		reloadUpdateMgr = new SwingUpdateManager(100, 60000, () -> doReload());
	}

	@Override
	public void init() {
		super.init();

		provider = new DataWindowProvider(this);
		createActions();
	}

	@Override
	public void dispose() {
		reloadUpdateMgr.dispose();
		resetUpdateMgr.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		provider.dispose();
		super.dispose();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			resetTypes();
			reload();
			return;
		}
		if (ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_RENAMED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_REPLACED) ||
			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED)) {
			resetTypes();
		}
		if (ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_REMOVED)) {
			reload();
			return;  // if we are going to reload, no need to check for data additions.
		}
		if (ev.containsEvent(ChangeManager.DOCR_CODE_ADDED)) {
			for (int i = 0; i < ev.numRecords(); ++i) {
				DomainObjectChangeRecord doRecord = ev.getChangeRecord(i);
				int eventType = doRecord.getEventType();
				if (eventType == ChangeManager.DOCR_CODE_ADDED) {
					ProgramChangeRecord rec = (ProgramChangeRecord) doRecord;
					if (rec.getNewValue() instanceof Data) {
						provider.dataAdded(rec.getStart());
					}
				}
			}
		}
	}

	void reload() {
		reloadUpdateMgr.update();
	}

	void doReload() {
		provider.reload();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ViewChangedPluginEvent) {
			if (filterAction.getViewMode() && provider.isVisible()) {
				reload();
			}
		}
		else {
			super.processEvent(event);
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		provider.programOpened(program);
		filterAction.programOpened(program);
		resetTypes();
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.programClosed();
		filterAction.programClosed();
	}

	Program getProgram() {
		return currentProgram;
	}

	ProgramSelection getSelection() {
		return currentSelection;
	}

	// Junit access
	DataWindowProvider getProvider() {
		return provider;
	}

	/**
	 * Create the action objects for this plugin.
	 */
	private void createActions() {

		selectAction = new MakeProgramSelectionAction(this, provider.getTable());
		tool.addLocalAction(provider, selectAction);

		filterAction = new FilterAction(this);
		filterAction.setEnabled(currentProgram != null);
		tool.addLocalAction(provider, filterAction);

		DockingAction selectionAction = new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, selectionAction);
	}

	void selectData(ProgramSelection selection) {
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", selection, currentProgram);
		firePluginEvent(pspe);
		processEvent(pspe);
	}

	private void resetTypes() {
		if (provider.isVisible()) {
			resetUpdateMgr.update();
		}
		else {
			resetTypesNeeded = true;
		}
	}

	private void doReset() {
		resetTypesNeeded = false;
		ArrayList<String> selectedList = filterAction.getSelectedTypes();

		filterAction.clearTypes();
		if (currentProgram != null) {
			DataTypeManager typeManager = currentProgram.getDataTypeManager();
			Iterator<DataType> itr = typeManager.getAllDataTypes();
			while (itr.hasNext()) {
				DataType type = itr.next();
				filterAction.addType(type.getDisplayName());
			}
			filterAction.selectTypes(selectedList);
			filterAction.repaint();
			provider.reload();
		}
	}

	public boolean typeEnabled(String type) {
		return filterAction.typeEnabled(type);
	}

	public AddressSet getLimitedAddresses() {
		if (filterAction.getSelectionMode()) {
			AddressSet ret = new AddressSet();
			AddressRangeIterator itr = currentSelection.getAddressRanges();
			while (itr.hasNext()) {
				ret.add(itr.next());
			}

			return ret;
		}

		if (filterAction.getViewMode()) {
			ProgramTreeService service = tool.getService(ProgramTreeService.class);
			if (service != null) {
				return service.getView();
			}
		}
		return null;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		filterAction.setSelected(true);
	}

	public void dataWindowShown() {
		if (resetTypesNeeded) {
			resetTypes();
		}

	}

}
