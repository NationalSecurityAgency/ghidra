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
package ghidra.app.plugin.core.data;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.cmd.data.CreateStructureCmd;
import ghidra.app.cmd.data.CreateStructureInStructureCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;

/**
 * Action class to create structures
 */
class CreateStructureAction extends ListingContextAction {

	private static final String[] CREATE_STRUCTURE_POPUP_MENU =
		new String[] { "Data", "Create Structure..." };

	private DataPlugin plugin;
	private CreateStructureDialog createStructureDialog;

	/**
	 * Constructor
	 * @param name action name
	 * @param owner owner of this action (the plugin name)
	 */
	public CreateStructureAction(DataPlugin plugin) {
		super("Create Structure", plugin.getName());
// ACTIONS - auto generated
		setPopupMenuData(new MenuData(CREATE_STRUCTURE_POPUP_MENU, null, "BasicData"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_OPEN_BRACKET, InputEvent.SHIFT_DOWN_MASK));

		this.plugin = plugin;
		setEnabled(true);
		createStructureDialog = new CreateStructureDialog(plugin.getTool());
	}

	@Override
	public void dispose() {
		super.dispose();

		createStructureDialog.dispose();
	}

	/**
	 * Method called when the action is invoked.
	 */
	@Override
	public void actionPerformed(ListingActionContext programActionContext) {
		Program program = programActionContext.getProgram();
		ProgramSelection sel = programActionContext.getSelection();

		if (sel != null && !sel.isEmpty()) {
			InteriorSelection interiorSel = sel.getInteriorSelection();
			if (interiorSel != null) {
				createStructureInStructure(program, interiorSel);
			}
			else {
				createStructureInProgram(program, sel);
			}
		}
	}

	private void createStructureInStructure(Program program, InteriorSelection sel) {
		PluginTool tool = plugin.getTool();
		ProgramLocation from = sel.getFrom();
		ProgramLocation to = sel.getTo();
		Data data = program.getListing().getDataContaining(from.getAddress());
		Data comp = null;
		if (data != null) {
			comp = data.getComponent(from.getComponentPath());
		}

		if (comp == null) {
			tool.setStatusInfo("Create Structure Failed! No data at " + from.getAddress());
			return;
		}

		DataType parentDataType = comp.getParent().getBaseDataType();
		if (!(parentDataType instanceof Structure)) {
			tool.setStatusInfo("Cannot create structure here");
			return;
		}

		Address newStructureAddress = from.getAddress();
		int[] fromPath = from.getComponentPath();
		int[] toPath = to.getComponentPath();
		Structure tempStructure = null;
		try {
			tempStructure = StructureFactory.createStructureDataTypeInStrucuture(program,
				newStructureAddress, fromPath, toPath);
		}
		catch (Exception exc) {
			tool.setStatusInfo("Create structure failed: " + exc.getMessage());
			return;
		}

		Structure userChoice =
			createStructureDialog.showCreateStructureDialog(program, tempStructure);

		if (userChoice != null) {
			CreateStructureInStructureCmd cmd = new CreateStructureInStructureCmd(userChoice,
				newStructureAddress, fromPath, toPath);

			if (!tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
			else {
				plugin.updateRecentlyUsed(cmd.getNewDataType());
			}
		}
	}

	private void createStructureInProgram(Program program, ProgramSelection sel) {
		PluginTool tool = plugin.getTool();

		if (sel.getNumAddressRanges() > 1) {
			tool.setStatusInfo("Can only create structure on contiguous selection");
			return;
		}
		if (sel.getNumAddresses() > Integer.MAX_VALUE) {
			tool.setStatusInfo("Can't create structures greater than 0x7fffffff bytes");
			return;
		}

		Data data = program.getListing().getDataContaining(sel.getMinAddress());
		if (data == null) {
			tool.setStatusInfo("Create structure failed! No data at " + sel.getMinAddress());
			return;
		}

		Address structureAddress = sel.getMinAddress();
		int structureLength = (int) sel.getNumAddresses();

		// create a temporary structure to compare with the data types
		// in the current sytem
		Structure tempStructure = null;
		try {
			tempStructure = StructureFactory.createStructureDataType(program, structureAddress,
				structureLength);
		}
		catch (Exception exc) {
			tool.setStatusInfo("Create structure failed: " + exc.getMessage());
			return;
		}

		Structure userChoice =
			createStructureDialog.showCreateStructureDialog(program, tempStructure);

		// exit if the user cancels the operation
		if (userChoice != null) {
			CreateStructureCmd cmd = new CreateStructureCmd(userChoice, structureAddress);

			if (!tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
			else {
				plugin.updateRecentlyUsed(cmd.getNewDataType());
			}
		}
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		ProgramSelection sel = context.getSelection();
		if (sel != null && !sel.isEmpty()) {
			return plugin.isCreateDataAllowed(context);
		}
		return false;
	}
}
