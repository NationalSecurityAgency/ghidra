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
package ghidra.app.plugin.core.table;

import java.awt.Color;
import java.util.*;

import javax.swing.ImageIcon;

import docking.ComponentProvider;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.MarkerService;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.app.tablechooser.TableChooserExecutor;
import ghidra.app.util.query.TableService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Swing;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.task.SwingUpdateManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Results table service",
	description = "Provides a generic results service that takes a list of information "
			+ "and displays the list to user in the form of a table",
	servicesProvided = { TableService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class TableServicePlugin extends ProgramPlugin
		implements TableService, DomainObjectListener {

	private SwingUpdateManager updateMgr;
	private Map<Program, List<TableComponentProvider<?>>> programMap = new HashMap<>();

	private Map<Program, List<TableChooserDialog>> programToDialogMap = new HashMap<>();

	public TableServicePlugin(PluginTool tool) {
		super(tool, false, false);

		updateMgr = new SwingUpdateManager(1000, () -> updateProviders());

		createActions();
	}

	private void createActions() {
		//
		// Unusual Code: We, as a plugin, don't have any actions.  Our transient tables do have
		// 			     actions.  We need a way to have keybindings shared for all the different
		//				 actions.  Further, we need to register them now, not when the transient
		//               providers are created, as they would only appear in the options at
		//               that point.
		//
		DeleteTableRowAction.registerDummy(tool, getName());
	}

	@Override
	protected void dispose() {
		programMap.clear();
		updateMgr.dispose();
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program p = ((ProgramClosedPluginEvent) event).getProgram();
			closeAllQueries(p);
		}
		else {
			super.processEvent(event);
		}
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	private void closeAllQueries(Program program) {
		clearTableComponentProviders(program);
		clearTableDialogs(program);
	}

	private void clearTableComponentProviders(Program program) {
		List<TableComponentProvider<?>> plist = programMap.get(program);
		if (plist == null) {
			return;
		}
		// make a copy of the list because the provider updates the list
		List<TableComponentProvider<?>> list = new ArrayList<>(plist);
		for (int i = 0; i < list.size(); i++) {
			ComponentProvider provider = list.get(i);
			provider.closeComponent();
		}
		programMap.remove(program);
	}

	private void clearTableDialogs(Program program) {
		List<TableChooserDialog> dlist = programToDialogMap.get(program);
		if (dlist == null) {
			return;
		}
		// make a copy of the list because the dialog updates the list
		List<TableChooserDialog> list = new ArrayList<>(dlist);
		for (int i = 0; i < list.size(); i++) {
			TableChooserDialog dialog = list.get(i);
			dialog.close();
		}
		programMap.remove(program);
	}

	@Override
	public <T> TableComponentProvider<T> showTable(String title, String tableTypeName,
			GhidraProgramTableModel<T> model, String windowSubMenu, Navigatable navigatable) {

		GoToService gotoService = tool.getService(GoToService.class);

		if (gotoService != null && navigatable == null) {
			navigatable = gotoService.getDefaultNavigatable();
		}

		Program program = model.getProgram();

		TableComponentProvider<T> cp = new TableComponentProvider<>(this, title, tableTypeName,
			model, program.getDomainFile().getName(), gotoService, windowSubMenu, navigatable);
		addProvider(program, cp);
		return cp;
	}

	@Override
	public <T> TableComponentProvider<T> showTableWithMarkers(String title, String tableTypeName,
			GhidraProgramTableModel<T> model, Color markerColor, ImageIcon markerIcon,
			String windowSubMenu, Navigatable navigatable) {

		GoToService gotoService = tool.getService(GoToService.class);

		if (gotoService != null && navigatable == null) {
			navigatable = gotoService.getDefaultNavigatable();
		}

		MarkerService markerService = tool.getService(MarkerService.class);
		Program program = model.getProgram();

		TableComponentProvider<T> cp = new TableComponentProvider<>(this, title, tableTypeName,
			model, program.getDomainFile().getName(), gotoService, markerService, markerColor,
			markerIcon, windowSubMenu, navigatable);
		addProvider(program, cp);
		return cp;
	}

	private void addProvider(Program program, TableComponentProvider<?> provider) {
		List<TableComponentProvider<?>> list = programMap.get(program);
		if (list == null) {
			list = new ArrayList<>();
			programMap.put(program, list);
		}
		list.add(provider);
	}

	void remove(TableComponentProvider<?> provider) {
		Iterator<Program> iter = programMap.keySet().iterator();
		while (iter.hasNext()) {
			Program p = iter.next();
			List<TableComponentProvider<?>> list = programMap.get(p);
			if (list.remove(provider)) {
				if (list.size() == 0) {
					programMap.remove(p);
					return;
				}
			}
		}
	}

	void removeDialog(MyTableChooserDialog dialog) {
		Iterator<Program> iter = programToDialogMap.keySet().iterator();
		while (iter.hasNext()) {
			Program p = iter.next();
			List<TableChooserDialog> list = programToDialogMap.get(p);
			if (list.remove(dialog)) {
				if (list.size() == 0) {
					programToDialogMap.remove(p);
					return;
				}
			}
		}
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		updateMgr.update();
	}

	public TableComponentProvider<?>[] getManagedComponents() {
		List<TableComponentProvider<?>> clist = getProviders();
		return clist.toArray(new TableComponentProvider[clist.size()]);
	}

	Program getProgram() {
		return currentProgram;
	}

	private List<TableComponentProvider<?>> getProviders() {
		List<TableComponentProvider<?>> clist = new ArrayList<>();
		Iterator<List<TableComponentProvider<?>>> iter = programMap.values().iterator();
		while (iter.hasNext()) {
			List<TableComponentProvider<?>> list = iter.next();
			clist.addAll(list);
		}
		return clist;
	}

	private void updateProviders() {
		List<TableComponentProvider<?>> list = getProviders();
		for (int i = 0; i < list.size(); i++) {
			TableComponentProvider<?> provider = list.get(i);
			provider.refresh();
		}
	}

	@Override
	public TableChooserDialog createTableChooserDialog(TableChooserExecutor executor,
			Program program, String title, Navigatable navigatable) {

		return createTableChooserDialog(executor, program, title, navigatable, false);
	}

	@Override
	public TableChooserDialog createTableChooserDialog(TableChooserExecutor executor,
			Program program, String title, Navigatable navigatable, boolean isModal) {

		GoToService gotoService = tool.getService(GoToService.class);

		if (gotoService != null && navigatable == null) {
			navigatable = gotoService.getDefaultNavigatable();
		}

		Navigatable nav = navigatable;
		TableChooserDialog dialog = Swing.runNow(
			() -> new MyTableChooserDialog(this, executor, program, title, nav, isModal));

		List<TableChooserDialog> list =
			programToDialogMap.computeIfAbsent(program, p -> new ArrayList<>());
		list.add(dialog);
		return dialog;
	}
}
