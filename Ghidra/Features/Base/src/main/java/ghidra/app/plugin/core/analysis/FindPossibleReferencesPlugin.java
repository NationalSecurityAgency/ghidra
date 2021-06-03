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
package ghidra.app.plugin.core.analysis;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Plugin to find all possible references to the address at the
 * current cursor location.  A reference is some set of bytes that
 * when treated as an address would be the address of the current
 * cursor location.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Search for Direct References",
	description = "Plugin to find all possible direct references to the address at the "
			+ "current cursor location.  A direct reference is some set of bytes that when"
			+ "treated as an address, match the address of the current cursor location.",
	servicesRequired = { GoToService.class, TableService.class },
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on
public class FindPossibleReferencesPlugin extends Plugin {
	final static String RESTORE_SELECTION_ACTION_NAME = "Restore Direct Refs Search Selection";
	final static String SEARCH_DIRECT_REFS_ACTION_NAME = "Search for Direct References";
	final static String SEARCH_DIRECT_REFS_ACTION_HELP = "Direct_Refs_Search_Alignment";
	private DockingAction action;
	private ArrayList<TableComponentProvider<ReferenceAddressPair>> providerList;

	public FindPossibleReferencesPlugin(PluginTool tool) {
		super(tool);
		createActions();
		providerList = new ArrayList<>();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent) {
			Program program = ((ProgramClosedPluginEvent) event).getProgram();
			programClosed(program);
			return;
		}
	}

	private void programClosed(Program program) {
		List<TableComponentProvider<ReferenceAddressPair>> list = new ArrayList<>(providerList);

		for (int i = 0; i < list.size(); i++) {
			TableComponentProvider<ReferenceAddressPair> p = list.get(i);
			FindReferencesTableModel model = (FindReferencesTableModel) p.getModel();
			if (program == model.getProgram()) {
				providerList.remove(p);
			}
		}
	}

	private void createActions() {
		action = new ActionBuilder(SEARCH_DIRECT_REFS_ACTION_NAME, getName())
				.menuPath(ToolConstants.MENU_SEARCH, "For Direct References")
				.menuGroup("search for")
				.supportsDefaultToolContext(true)
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, SEARCH_DIRECT_REFS_ACTION_NAME))
				.description(getPluginDescription().getDescription())
				.withContext(NavigatableActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(this::findReferences)
				.enabledWhen(this::hasCorrectAddressSize)
				.buildAndInstall(tool);

	}

	private boolean hasCorrectAddressSize(NavigatableActionContext context) {
		int size =
			context.getProgram().getAddressFactory().getDefaultAddressSpace().getSize();
		if ((size == 64) || (size == 32) || (size == 24) || (size == 16) || (size == 20) ||
			(size == 21)) {
			return true;
		}
		return false;
	}

	private void createLocalActions(NavigatableActionContext context, ComponentProvider p,
			FindReferencesTableModel model) {

		addLocalAlignment(p, model, 1);
		addLocalAlignment(p, model, 2);
		addLocalAlignment(p, model, 3);
		addLocalAlignment(p, model, 4);
		addLocalAlignment(p, model, 8);

		final ProgramSelection selection = context.getSelection();
		final Program pgm = context.getProgram();
		DockingAction localAction = new DockingAction(RESTORE_SELECTION_ACTION_NAME, getName()) {
			@Override
			public void actionPerformed(ActionContext actionContext) {
				restoreSearchSelection(selection, pgm);
			}
		};
		localAction.setEnabled(false);
		localAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, RESTORE_SELECTION_ACTION_NAME));
		String group = "selection";
		localAction.setMenuBarData(
			new MenuData(new String[] { "Restore Search Selection" }, group));
		localAction.setPopupMenuData(
			new MenuData(new String[] { "Restore Search Selection" }, group));

		localAction.setDescription(
			"Sets the program selection back to the selection this search was based upon.");
		if (selection != null && !selection.isEmpty()) {
			localAction.setEnabled(true);
			tool.addLocalAction(p, localAction);
		}
	}

	private UpdateAlignmentAction addLocalAlignment(ComponentProvider p,
			FindReferencesTableModel model, int alignment) {

		UpdateAlignmentAction alignAction =
			new ghidra.app.plugin.core.analysis.UpdateAlignmentAction(this, model, alignment);

		alignAction.setEnabled(alignment >= model.getAlignment());
		alignAction.setHelpLocation(
			new HelpLocation(HelpTopics.SEARCH, SEARCH_DIRECT_REFS_ACTION_HELP));

		tool.addLocalAction(p, alignAction);
		return alignAction;
	}

	protected void restoreSearchSelection(ProgramSelection selection, Program program) {
		PluginEvent event = new ProgramSelectionPluginEvent(getName(), selection, program);
		tool.firePluginEvent(event);
	}

	/**
	 * find possible references to current address
	 */
	private void findReferences(NavigatableActionContext context) {
		AddressSetView fromSet = context.getSelection();
		Address fromAddr = context.getAddress();
		Program currentProgram = context.getProgram();
		ProgramSelection currentSelection = context.getSelection();
		if (fromAddr == null) {
			return;
		}

		String title;
		if (currentSelection == null || currentSelection.isEmpty()) {
			if (currentProgram.getMemory().getBlock(fromAddr) == null) {
				Msg.showWarn(getClass(), null, "Search For Direct References",
					"Could not find memory associated with " + fromAddr);
				return;
			}
			if (currentProgram.getMemory()
					.getBlock(
						fromAddr)
					.getType() == MemoryBlockType.BIT_MAPPED) {
				Msg.showWarn(getClass(), null, "Search For Direct References",
					"Cannot search for direct references on bit memory!");
				return;
			}
			fromSet = getAddressSetForCodeUnitAt(currentProgram, fromAddr);
			title = ": Direct Refs to " + fromAddr;
		}
		else {
			title = ": Direct Refs to Selection @ " + currentSelection.getMinAddress();
		}

		List<TableComponentProvider<ReferenceAddressPair>> list = new ArrayList<>(providerList);
		for (int i = 0; i < list.size(); i++) {
			TableComponentProvider<ReferenceAddressPair> p = list.get(i);
			if (!tool.isVisible(p)) {
				providerList.remove(p);
			}
			else {
				FindReferencesTableModel model = (FindReferencesTableModel) p.getModel();
				AddressSetView searchSet = model.getSearchAddressSet();
				Address searchAddr = model.getAddress();
				// If this model matches the search about to be performed.
				// (i.e. same search address set or same individual address)
				if (((fromSet != null && !fromSet.isEmpty()) && (fromSet.equals(searchSet))) ||
					(((fromSet == null) || fromSet.isEmpty()) && fromAddr.equals(searchAddr))) {
					model.refresh();
					tool.showComponentProvider(p, true);
					return;
				}
			}
		}
		FindReferencesTableModel model = null;

		model = new FindReferencesTableModel(fromSet, tool, currentProgram);

		TableService service = tool.getService(TableService.class);
		TableComponentProvider<ReferenceAddressPair> p =
			service.showTable("Find References to" + title, getName(), model, "Possible References",
				context.getNavigatable());
		p.installRemoveItemsAction();
		p.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Search for Direct References"));
		createLocalActions(context, p, model);
		providerList.add(p);
	}

	private AddressSet getAddressSetForCodeUnitAt(Program program, Address fromAddr) {
		AddressSet set = new AddressSet();
		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(fromAddr);
		if (codeUnit == null) {
			set.addRange(fromAddr, fromAddr);
		}
		else {
			set.addRange(codeUnit.getMinAddress(), codeUnit.getMaxAddress());
		}
		return set;
	}

}
