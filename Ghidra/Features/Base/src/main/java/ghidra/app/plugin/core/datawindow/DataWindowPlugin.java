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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.util.*;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.events.ViewChangedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramTreeService;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramSelection;
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
public class DataWindowPlugin extends ProgramPlugin {

	private DockingAction selectAction;
	private FilterAction filterAction;
	private DataWindowProvider provider;

	private SwingUpdateManager resetUpdateMgr;
	private SwingUpdateManager reloadUpdateMgr;
	private boolean resetTypesNeeded;
	private DomainObjectListener domainObjectListener = createDomainObjectListener();

	private SortedMap<String, Boolean> typeEnablementByDisplayName =
		new TreeMap<>(new DataTypeNameComparator());

	private boolean isFilterEnabled = false;
	private Coverage coverage = Coverage.PROGRAM;

	public DataWindowPlugin(PluginTool tool) {
		super(tool);

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
			currentProgram.removeListener(domainObjectListener);
		}
		provider.dispose();
		super.dispose();
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.any(RESTORED)
				.terminate(() -> resetTypes())
			.any(MEMORY_BLOCK_ADDED, MEMORY_BLOCK_REMOVED, CODE_REMOVED)
				.terminate(e -> reload())
			.any(DATA_TYPE_ADDED,DATA_TYPE_CHANGED, DATA_TYPE_MOVED, DATA_TYPE_RENAMED, 
				   DATA_TYPE_REPLACED, DATA_TYPE_SETTING_CHANGED)
				.terminate(() -> resetTypes())
			.with(ProgramChangeRecord.class)
				.each(CODE_ADDED).call(r -> codeAdded(r))
			.build();
		// @formatter:on
	}

	private void codeAdded(ProgramChangeRecord rec) {
		if (rec.getNewValue() instanceof Data) {
			provider.dataAdded(rec.getStart());
		}
	}

	void dataWindowShown() {
		if (resetTypesNeeded) {
			resetTypes();
		}

	}

	void setFilterEnabled(boolean enabled) {
		isFilterEnabled = enabled;
		reload();
	}

	void setFilter(SortedMap<String, Boolean> typeEnabledMap, Coverage coverage) {
		this.isFilterEnabled = true;
		this.typeEnablementByDisplayName = new TreeMap<>(typeEnabledMap);
		this.coverage = coverage;
		reload();
	}

	private void reload() {
		reloadUpdateMgr.update();
	}

	private void doReload() {
		provider.reload();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ViewChangedPluginEvent) {
			if (isFilterEnabled && provider.isVisible()) {
				reload();
			}
		}
		else {
			super.processEvent(event);
		}
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(domainObjectListener);
		provider.programOpened(program);
		filterAction.setEnabled(true);
		resetTypes();
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(domainObjectListener);
		provider.programClosed();
		filterAction.setEnabled(false);
	}

	Program getProgram() {
		return currentProgram;
	}

	ProgramSelection getSelection() {
		return currentSelection;
	}

	// test access
	DataWindowProvider getProvider() {
		return provider;
	}

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
		typeEnablementByDisplayName.clear();
		if (currentProgram == null) {
			return;
		}

		DataTypeManager dtm = currentProgram.getDataTypeManager();
		Iterator<DataType> it = dtm.getAllDataTypes();
		while (it.hasNext()) {
			DataType type = it.next();
			typeEnablementByDisplayName.put(type.getDisplayName(), true);
		}

		provider.reload();
	}

	boolean isTypeEnabled(String type) {
		if (!isFilterEnabled) {
			return true;
		}

		Boolean enabled = typeEnablementByDisplayName.get(type);
		return enabled != null && enabled;
	}

	SortedMap<String, Boolean> getTypeMap() {
		return typeEnablementByDisplayName;
	}

	AddressSet getLimitedAddresses() {
		if (coverage == Coverage.SELECTION) {
			AddressSet addrs = new AddressSet();
			AddressRangeIterator it = currentSelection.getAddressRanges();
			while (it.hasNext()) {
				addrs.add(it.next());
			}

			return addrs;
		}

		if (coverage == Coverage.VIEW) {
			ProgramTreeService service = tool.getService(ProgramTreeService.class);
			if (service != null) {
				return service.getView();
			}
		}

		return null; // PROGRAM
	}

	private static class DataTypeNameComparator implements Comparator<String> {

		@Override
		public int compare(String o1, String o2) {
			if (o1 != null) {
				if (!o1.equalsIgnoreCase(o2)) {
					return o1.compareToIgnoreCase(o2);
				}
				return o1.compareTo(o2);
			}
			return -1;
		}
	}

	public enum Coverage {
		//@formatter:off
		PROGRAM("Entire Program"), 
		SELECTION("Current Selection"), 
		VIEW("Current View");
		//@formatter:on

		private String displayName;

		Coverage(String displayName) {
			this.displayName = displayName;
		}

		@Override
		public String toString() {
			return displayName;
		}
	}
}
