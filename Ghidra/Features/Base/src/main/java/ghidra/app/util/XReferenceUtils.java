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
package ghidra.app.util;

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.util.*;
import java.util.function.Supplier;

import javax.swing.Icon;
import javax.swing.JTable;

import docking.ActionContext;
import docking.action.*;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.OptionDialogBuilder;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.query.TableService;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.model.DomainObjectListenerBuilder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.table.ReferencesFromTableModel;
import ghidra.util.table.field.ReferenceEndpoint;
import resources.Icons;
import resources.ResourceManager;

public class XReferenceUtils {

	private static final String X_REFS_TO = "XRefs to ";

	// Methods in this class treat -1 as a key to return all references and not cap the result set.
	private final static int ALL_REFS = -1;

	private static OptionDialog promptToDeleteXrefsDialog;

	/**
	 * Returns an array containing the first <b><code>max</code></b>
	 * direct xref references to the specified code unit.
	 *
	 * @param cu the code unit to generate the xrefs
	 * @param max max number of xrefs to get, or -1 to get all references
	 *
	 * @return array first <b><code>max</code></b> xrefs to the code unit
	 */
	public final static List<Reference> getXReferences(CodeUnit cu, int max) {
		Program program = cu.getProgram();
		if (program == null) {
			Collections.emptyList();
		}

		// lookup the direct xrefs to the current code unit
		List<Reference> xrefs = new ArrayList<>();
		Address minAddress = cu.getMinAddress();
		ReferenceIterator it = program.getReferenceManager().getReferencesTo(minAddress);
		while (it.hasNext()) {
			if (xrefs.size() - max == 0) {
				break;
			}

			Reference ref = it.next();
			xrefs.add(ref);
		}

		// Check for thunk reference
		Function function = program.getFunctionManager().getFunctionAt(minAddress);
		if (function == null) {
			return xrefs;
		}

		Address[] thunkAddrs = function.getFunctionThunkAddresses(false);
		if (thunkAddrs != null) {
			for (Address thunkAddr : thunkAddrs) {
				xrefs.add(new ThunkReference(thunkAddr, function.getEntryPoint()));
			}
		}
		return xrefs;
	}

	/**
	 * Returns an array containing all offcut xref references to the specified code unit
	 *
	 * @param cu the code unit to generate the offcut xrefs
	 * @param max max number of offcut xrefs to get, or -1 to get all offcut references
	 * @return array of all offcut xrefs to the code unit
	 */
	public static List<Reference> getOffcutXReferences(CodeUnit cu, int max) {
		Program program = cu.getProgram();
		if (program == null) {
			return Collections.emptyList();
		}

		if (cu.getLength() <= 1) {
			return Collections.emptyList();
		}

		List<Reference> offcuts = new ArrayList<>();
		ReferenceManager refMgr = program.getReferenceManager();
		AddressSet set = new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
		AddressIterator it = refMgr.getReferenceDestinationIterator(set, true);
		while (it.hasNext()) {
			Address addr = it.next();
			ReferenceIterator refIter = refMgr.getReferencesTo(addr);
			while (refIter.hasNext()) {
				if (offcuts.size() - max == 0) {
					break;
				}

				Reference ref = refIter.next();
				offcuts.add(ref);
			}
		}

		return offcuts;
	}

	/**
	 * Populates the provided lists with the direct and offcut xrefs to the specified variable
	 *
	 * @param var     variable to get references
	 * @param xrefs   list to put direct references in
	 * @param offcuts list to put offcut references in
	 */
	public static void getVariableRefs(Variable var, List<Reference> xrefs,
			List<Reference> offcuts) {
		getVariableRefs(var, xrefs, offcuts, ALL_REFS);
	}

	/**
	 * Populates the provided lists with the direct and offcut xrefs to the specified variable
	 *
	 * @param var     variable to get references
	 * @param xrefs   list to put direct references in
	 * @param offcuts list to put offcut references in
	 * @param max max number of xrefs to get, or -1 to get all references
	 */
	public static void getVariableRefs(Variable var, List<Reference> xrefs, List<Reference> offcuts,
			int max) {

		Address addr = var.getMinAddress();
		if (addr == null) {
			return;
		}

		Program program = var.getFunction().getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] refs = refMgr.getReferencesTo(var);
		int total = 0;
		for (Reference vref : refs) {
			if (total++ - max == 0) {
				break;
			}

			if (addr.equals(vref.getToAddress())) {
				xrefs.add(vref);
			}
			else {
				offcuts.add(vref);
			}
		}
	}

	/**
	 * Returns all xrefs to the given location.  If in data, then xrefs to the specific data
	 * component will be returned.  Otherwise, the code unit containing the address of the
	 * given location will be used as the source of the xrefs.
	 *
	 * @param location the location for which to get xrefs
	 * @return the xrefs
	 */
	public static Set<Reference> getAllXrefs(ProgramLocation location) {

		CodeUnit cu = DataUtilities.getDataAtLocation(location);
		if (cu == null) {
			Address toAddress = location.getAddress();
			Listing listing = location.getProgram().getListing();
			cu = listing.getCodeUnitContaining(toAddress);
		}

		if (cu == null) {
			return Collections.emptySet();
		}

		List<Reference> xrefs = getXReferences(cu, ALL_REFS);
		List<Reference> offcuts = getOffcutXReferences(cu, ALL_REFS);

		// Remove duplicates
		Set<Reference> set = new HashSet<>();
		set.addAll(xrefs);
		set.addAll(offcuts);
		return set;
	}

	/**
	 * Shows all xrefs to the given location in a new table.
	 *
	 * @param navigatable the navigatable used for navigation from the table
	 * @param serviceProvider the service provider needed to wire navigation
	 * @param service the service needed to show the table
	 * @param location the location for which to find references
	 * @param xrefs the xrefs to show
	 * @deprecated use {@link #showXrefs(Navigatable, ServiceProvider, TableService, 
	 * 	ProgramLocation, Supplier)}.  That method takes a supplier that can regenerate the current
	 *  xrefs for the table.
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public static void showXrefs(Navigatable navigatable, ServiceProvider serviceProvider,
			TableService service, ProgramLocation location, Collection<Reference> xrefs) {

		showXrefs(navigatable, serviceProvider, service, location, () -> xrefs);
	}

	/**
	 * Shows all xrefs to the given location in a new table.
	 * 
	 * @param navigatable the navigatable used for navigation from the table
	 * @param serviceProvider the service provider needed to wire navigation
	 * @param service the service needed to show the table
	 * @param location the location for which to find references
	 * @param xrefs a supplier of the xrefs to show
	 */
	public static void showXrefs(Navigatable navigatable, ServiceProvider serviceProvider,
			TableService service, ProgramLocation location, Supplier<Collection<Reference>> xrefs) {

		Address address = location.getAddress();
		Program program = location.getProgram();
		FunctionManager fm = program.getFunctionManager();
		Function function = fm.getFunctionAt(address);

		ReferencesFromTableModel model;
		if (function == null) {
			model = new ReferencesFromTableModel(xrefs, serviceProvider, program);
		}
		else {
			model = new FunctionXrefsTableModel(function, xrefs, serviceProvider, program);
		}

		String title = generateXRefTitle(location);
		TableComponentProvider<ReferenceEndpoint> provider =
			service.showTable(title, "Xrefs", model, "Xrefs", navigatable);

		// 
		// Add Actions
		// 
		provider.installRemoveItemsAction();

		installRefreshAction(provider, model);

		if (function != null) {
			installShowThunksAction(provider, model);
		}

		DeleteXrefsAction deleteAction = new DeleteXrefsAction(provider, model, program);
		provider.addLocalAction(deleteAction);
	}

	private static void installShowThunksAction(
			TableComponentProvider<ReferenceEndpoint> provider,
			ReferencesFromTableModel model) {

		//@formatter:off
		String actionName = "Show Thunk Xrefs";
		new ToggleActionBuilder(actionName, provider.getActionOwner())
			.toolBarIcon(ResourceManager.loadImage("images/ThunkFunction.gif"))
			.toolBarGroup("A")
			.helpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, actionName))
			.selected(false)
			.onAction(c -> {
				((FunctionXrefsTableModel) model).toggleShowAllThunkXRefs();
			})
			.buildAndInstallLocal(provider);
		//@formatter:on
	}

	private static void installRefreshAction(TableComponentProvider<ReferenceEndpoint> provider,
			ReferencesFromTableModel model) {

		Icon REFRESH_NOT_NEEDED_ICON = ResourceManager.getDisabledIcon(Icons.REFRESH_ICON, 60);
		DockingAction refreshAction = new DockingAction("Refresh", provider.getActionOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				getToolBarData().setIcon(REFRESH_NOT_NEEDED_ICON);
				model.reload();
			}
		};
		HelpLocation hl = new HelpLocation(HelpTopics.CODE_BROWSER, refreshAction.getName());
		refreshAction.setHelpLocation(hl);
		refreshAction.setToolBarData(new ToolBarData(REFRESH_NOT_NEEDED_ICON, "A"));
		refreshAction.setDescription(
			"<html>Push at any time to refresh the current table of references.<br>" +
				"This button is highlighted when the data <i>may</i> be stale.<br>");

		// Add a listener to 
		DomainObjectListener listener = new DomainObjectListenerBuilder(model)
				.any(RESTORED, REFERENCE_ADDED, REFERENCE_REMOVED)
				.call(() -> {
					// signal that the data in the table does not match the program
					refreshAction.getToolBarData().setIcon(Icons.REFRESH_ICON);
				})
				.build();
		provider.setProgramListener(listener);
		provider.addLocalAction(refreshAction);
	}

	// Note: this action lives in this class so that the action can hold a reference to a domain
	// object listener.  The action will hold a reference so that as long as the the provider is 
	// around, the action will also be around to hold a reference to the listener.
	private static class DeleteXrefsAction extends DockingAction {

		private TableComponentProvider<ReferenceEndpoint> provider;
		private Program program;
		private ReferencesFromTableModel tableModel;

		public DeleteXrefsAction(TableComponentProvider<ReferenceEndpoint> provider,
				ReferencesFromTableModel tableModel, Program program) {
			super("Delete Reference", provider.getActionOwner(), KeyBindingType.SHARED);
			this.provider = provider;
			this.tableModel = tableModel;
			this.program = program;

			setToolBarData(new ToolBarData(Icons.DELETE_ICON, "A"));
			setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, getName()));
		}

		@Override
		public boolean isEnabledForContext(ActionContext c) {
			Object object = c.getContextObject();
			if (!(object instanceof JTable table)) {
				return false;
			}
			if (tableModel.isBusy()) {
				return false;
			}
			return table.getSelectedRowCount() > 0;
		}

		@Override
		public void actionPerformed(ActionContext c) {
			Object object = c.getContextObject();
			JTable table = (JTable) object;
			int[] rows = table.getSelectedRows();
			PluginTool tool = provider.getTool();
			deleteXrefs(tool, program, tableModel, rows);
		}

	}

	private static void deleteXrefs(PluginTool tool, Program program,
			ReferencesFromTableModel tableModel, int[] rows) {

		if (promptToDeleteXrefsDialog == null) {
			promptToDeleteXrefsDialog =
				new OptionDialogBuilder("Delete Xrefs?",
					"Do you wish to permanently delete the selected xrefs?")
							.addOption("Delete")
							.addCancel()
							.addDontShowAgainOption()
							.build();
		}

		int choice = promptToDeleteXrefsDialog.show();
		if (choice != OptionDialog.YES_OPTION) {
			return;
		}

		List<ReferenceEndpoint> deletedRowObjects = new ArrayList<>();
		CompoundCmd<Program> compoundCmd = new CompoundCmd<>("Delete References");
		for (int row : rows) {
			ReferenceEndpoint endpoint = tableModel.getRowObject(row);
			deletedRowObjects.add(endpoint);
			Reference ref = endpoint.getReference();
			RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
			compoundCmd.add(cmd);
		}
		tool.execute(compoundCmd, program);

		// also remove the object from the table, since they have been deleted
		deletedRowObjects.forEach(ro -> tableModel.removeObject(ro));
	}

	private static String generateXRefTitle(ProgramLocation location) {

		// note: we likely need to improve this title generation as we find more specific needs
		Program program = location.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Address address = location.getAddress();
		if (location instanceof VariableLocation) {
			VariableLocation vl = (VariableLocation) location;
			String name = vl.getVariable().getName();
			Function f = functionManager.getFunctionContaining(vl.getFunctionAddress());
			return X_REFS_TO + name + (f == null ? "" : " in " + f.getName());
		}
		else if (location instanceof FunctionLocation) {
			FunctionLocation fl = (FunctionLocation) location;
			Function f = functionManager.getFunctionContaining(fl.getFunctionAddress());
			if (f != null) {
				return X_REFS_TO + f.getName();
			}
		}
		else {
			Function f = functionManager.getFunctionAt(address);
			if (f != null) {
				return X_REFS_TO + f.getName();
			}
		}

		return X_REFS_TO + location.getAddress();
	}
}
