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
package ghidra.app.plugin.core.equate;

import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.OperandFieldLocation;
import ghidra.util.Msg;
import ghidra.util.task.SwingUpdateManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Displays the list of equates",
	description = "This plugin provides a window that displays all the equates that have been defined in the program."
)
//@formatter:on
public class EquateTablePlugin extends ProgramPlugin implements DomainObjectListener {

	private GoToService goToService;
	private EquateTableProvider provider;
	private SwingUpdateManager updateMgr;

	public EquateTablePlugin(PluginTool tool) {
		super(tool, true, false);

		updateMgr = new SwingUpdateManager(1000, 3000, () -> provider.updateEquates());

		provider = new EquateTableProvider(this);
	}

	@Override
	public void init() {
		super.init();

		goToService = tool.getService(GoToService.class);
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == GoToService.class) {
			provider.setGoToService((GoToService) service);
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == GoToService.class) {
			provider.setGoToService(null);
		}
	}

	@Override
	public void dispose() {
		updateMgr.dispose();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		provider.dispose();
		super.dispose();
	}

	////////////////////////////////////////////////////////////////////////////
	//
	//  Implementation of DomainObjectListener
	//
	////////////////////////////////////////////////////////////////////////////

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!provider.isVisible()) {
			return;
		}

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			updateMgr.updateNow();
			return;
		}
		if (ev.containsEvent(ChangeManager.DOCR_EQUATE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_EQUATE_REFERENCE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_EQUATE_REFERENCE_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_EQUATE_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_EQUATE_RENAMED) ||

			ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_SYMBOL_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_SYMBOL_RENAMED) ||

			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED) ||

			ev.containsEvent(ChangeManager.DOCR_FUNCTION_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_REMOVED) ||

			ev.containsEvent(ChangeManager.DOCR_CODE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_REMOVED) ||

			ev.containsEvent(ChangeManager.DOCR_DATA_TYPE_CHANGED)) {

			updateMgr.update();
		}

	}

	@Override
	protected void programActivated(Program program) {
		if (tool.isVisible(provider)) {
			program.addListener(this);
		}
		provider.programOpened(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		provider.programClosed();
	}

	void deleteEquates(List<Equate> equates) {
		if (equates.isEmpty()) {
			return;
		}

		// create a string list of names of all equates to be removed...
		String[] equateNames = new String[equates.size()];
		StringBuffer equateList = new StringBuffer();
		for (int i = 0; i < equates.size(); ++i) {
			equateNames[i] = equates.get(i).getName();
			equateList.append(equateNames[i]);
			if (i < equates.size() - 1) {
				equateList.append(", ");
			}
		}
		String title = "Delete Equate" + (equates.size() > 1 ? "s" : "") + "?";
		String msg = "Do you really want to delete the equate" + (equates.size() > 1 ? "s" : "") +
			": " + equates + "  ?" + "\n\n   NOTE: All references will be removed.";

		int option = OptionDialog.showOptionDialog(provider.getComponent(), title, msg, "Delete",
			OptionDialog.QUESTION_MESSAGE);

		if (option != OptionDialog.CANCEL_OPTION) {
			tool.execute(new RemoveEquateCmd(equateNames, getTool()), currentProgram);
		}
	}

	Program getProgram() {
		return currentProgram;
	}

	void goTo(Address addr, int operandIndex) {
		OperandFieldLocation loc =
			new OperandFieldLocation(currentProgram, addr, null, null, null, operandIndex, 0);
		goToService.goTo(loc);
	}

	// package-level access for Junit tests
	EquateTableProvider getProvider() {
		return provider;
	}

	/**
	 * Notification that the component is now showing.
	 */
	void componentShown() {
		if (currentProgram != null) {
			currentProgram.addListener(this);
		}
	}

	void componentClosed() {
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
	}

	/**
	 * Renames an equate either at the given reference location or at all references.
	 * @param oldEquate the equate that exists at the current location.
	 * @param newEquateName the new equate name to be used.
	 */
	void renameEquate(Equate oldEquate, String newEquateName) {

		// if not changed, do nothing
		String oldEquateName = oldEquate.getName();
		if (oldEquateName.equals(newEquateName)) {
			return;
		}

		if (isValid(oldEquate, newEquateName)) {
			Command cmd = new RenameEquatesCmd(oldEquateName, newEquateName);
			tool.execute(cmd, currentProgram);
		}
	}

	/**
	 * If the equate exists, checks to make sure the value matches the current scalar value
	 * 
	 * @param equate the equate to check
	 * @param equateStr the candidate equate name for the set or rename operation
	 * @return true if valid
	 */
	boolean isValid(Equate equate, String equateStr) {
		// these are valid in the sense that they represent a clear or remove operation
		if (equateStr == null || equateStr.length() <= 0) {
			return false;
		}

		EquateTable equateTable = currentProgram.getEquateTable();
		Equate newEquate = equateTable.getEquate(equateStr);
		if (newEquate != null && !newEquate.equals(equate)) {
			Msg.showInfo(getClass(), provider.getComponent(), "Rename Equate Failed!",
				"Equate " + equateStr + " exists with value 0x" +
					Long.toHexString(newEquate.getValue()) + " (" + newEquate.getValue() + ")");
			return false;
		}
		return true;
	}
}
