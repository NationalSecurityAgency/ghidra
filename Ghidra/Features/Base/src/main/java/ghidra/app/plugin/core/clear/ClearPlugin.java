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
package ghidra.app.plugin.core.clear;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

/**
 * Plugin that manages the 'clear' and 'clear with options' operations on a program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Clear Code and Program Annotations",
	description = "This plugin clears instructions and provides options to clear other program annotations, such as comments, labels, etc."
)
//@formatter:on
public class ClearPlugin extends Plugin {
	private static final String CLEAR_WITH_OPTIONS_NAME = "Clear With Options";
	private static final String CLEAR_CODE_BYTES_NAME = "Clear Code Bytes";
	private static final String CLEAR_FLOW_AND_REPAIR = "Clear Flow and Repair";

	private ClearDialog clearDialog;
	private ClearFlowDialog clearFlowDialog;

	/**
	 * Constructor
	 */
	public ClearPlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	// /////////////////////////////////////////////////////////////////////

	/**
	 * Clear the flow and repair disassembly at the current location
	 */
	void clearFlowAndRepair(ListingActionContext context, boolean clearSymbols, boolean clearData,
			boolean repair) {
		ClearFlowAndRepairCmd cmd;
		ProgramSelection selection = context.getSelection();
		ProgramLocation location = context.getLocation();
		if (selection == null || selection.isEmpty()) {
			cmd = new ClearFlowAndRepairCmd(location.getAddress(), clearData, clearSymbols, repair);
		}
		else {
			cmd = new ClearFlowAndRepairCmd(selection, clearData, clearSymbols, repair);
		}
		tool.executeBackgroundCommand(cmd, context.getProgram());
	}

	/**
	 * Use the options to determine what must be cleared. Starts a new thread if
	 * necessary to do the work. Called by the actions and by the dialog.
	 */
	void clear(ClearOptions options, ListingActionContext context) {
		if (!options.clearAny()) {
			return;
		}

		if (!scheduleClear(options, context)) {
			return;
		}

		AddressSet set = new AddressSet(context.getSelection());
		ClearCmd cmd = new ClearCmd(set, options);
		tool.executeBackgroundCommand(cmd, context.getProgram());
	}

	private boolean scheduleClear(ClearOptions options, ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		ProgramLocation location = context.getLocation();
		Program program = context.getProgram();

		if (selection == null || selection.isEmpty()) {
			clearWhenNoSelection(options, location, program);
			return false; // don't need a task to run...
		}

		InteriorSelection interSel = selection.getInteriorSelection();
		if (interSel != null) {
			clearStructure(program, interSel.getFrom(), interSel.getTo());
			return false;
		}
		return true;
	}

	private void clearWhenNoSelection(ClearOptions options, ProgramLocation location,
			Program program) {
		if (location == null) {
			return;
		}

		int[] compPath = location.getComponentPath();
		if (compPath != null && compPath.length > 0) {
			clearStructure(program, location, null);
			return;
		}

		CodeUnit cu = program.getListing().getCodeUnitContaining(location.getAddress());
		Command cmd = new ClearCmd(cu, options);
		tool.execute(cmd, program);
	}

	/**
	 * Clear the internal parts of a structure
	 */
	private boolean clearStructure(Program program, ProgramLocation start, ProgramLocation end) {
		// get data at start
		boolean commit = false;
		int id = program.startTransaction("Clear Structure");
		try {
			Address dataAddr = start.getByteAddress();
			Data data = program.getListing().getDefinedDataContaining(dataAddr);
			if (data == null) {
				return false;
			}

			// get the structure to clear, make sure it is a structure
			Data compData = data.getComponent(start.getComponentPath());
			if (compData == null) {
				return false;
			}

			DataType dataType = compData.getParent().getBaseDataType();
			if (!(dataType instanceof Composite)) {
				return false;
			}

			// get the start offset into the data structure
			int index = compData.getComponentIndex();
			int endIndex = index;
			if (end != null) {
				// assume start and end relate to ths same composite
				int[] cpath = end.getComponentPath();
				endIndex = cpath[cpath.length - 1];
			}

			if (dataType instanceof Union) {
				Union union = (Union) dataType;
				for (int ordinal = endIndex; ordinal >= 0 && ordinal >= index; ordinal--) {
					union.delete(ordinal);
				}
			}
			else {
				Structure structure = (Structure) dataType;
				for (int ordinal = endIndex; ordinal >= 0 && ordinal >= index; ordinal--) {
					structure.clearComponent(ordinal);
				}
			}
			commit = true;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		finally {
			program.endTransaction(id, commit);
		}
		return commit;
	}

	// /////////////////////////////////////////////////////////////////////
	// ** private methods
	// /////////////////////////////////////////////////////////////////////
	/**
	 * Create the actions.
	 */
	private void createActions() {
		new ActionBuilder(CLEAR_CODE_BYTES_NAME, getName())
				.menuPath(ToolConstants.MENU_EDIT, CLEAR_CODE_BYTES_NAME)
				.menuGroup(CLEAR_CODE_BYTES_NAME, "1")
				.popupMenuPath(CLEAR_CODE_BYTES_NAME)
				.popupMenuGroup(CLEAR_CODE_BYTES_NAME, "1")
				.keyBinding("C")
				.withContext(ListingActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.enabledWhen(this::isClearCodeBytesEnabled)
				.onAction(this::clearCodeBytes)
				.buildAndInstall(tool);

		new ActionBuilder(CLEAR_WITH_OPTIONS_NAME, getName())
				.menuPath(ToolConstants.MENU_EDIT, CLEAR_WITH_OPTIONS_NAME + "...")
				.menuGroup(CLEAR_CODE_BYTES_NAME, "2")
				.popupMenuPath(CLEAR_WITH_OPTIONS_NAME)
				.popupMenuGroup(CLEAR_CODE_BYTES_NAME, "2")
				.withContext(ListingActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(this::showClearAllDialog)
				.buildAndInstall(tool);

		new ActionBuilder(CLEAR_FLOW_AND_REPAIR, getName())
				.menuPath(ToolConstants.MENU_EDIT, CLEAR_FLOW_AND_REPAIR + "...")
				.menuGroup(CLEAR_CODE_BYTES_NAME, "3")
				.popupMenuPath(CLEAR_FLOW_AND_REPAIR)
				.popupMenuGroup(CLEAR_CODE_BYTES_NAME, "3")
				.withContext(ListingActionContext.class)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(this::showClearFlowDialog)
				.buildAndInstall(tool);
	}

	private boolean isClearCodeBytesEnabled(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		ProgramSelection currentSelection = context.getSelection();
		if (currentSelection != null && !currentSelection.isEmpty()) {
			return true;
		}
		else if ((loc != null) && (loc.getAddress() != null) && (loc instanceof CodeUnitLocation)) {
			return true;
		}
		return false;

	}

	private void clearCodeBytes(ListingActionContext context) {
		ClearOptions opts = new ClearOptions();

		opts.setClearCode(true);
		opts.setClearSymbols(false);
		opts.setClearComments(false);
		opts.setClearProperties(false);
		opts.setClearFunctions(false);
		opts.setClearRegisters(false);
		opts.setClearEquates(false);
		opts.setClearUserReferences(true);
		opts.setClearAnalysisReferences(true);
		opts.setClearImportReferences(true);
		opts.setClearDefaultReferences(false);
		opts.setClearBookmarks(false);

		clear(opts, context);

	}
	/**
	 * Pop up the clear with options dialog.
	 */
	private void showClearAllDialog(ListingActionContext programActionContext) {
		if (clearDialog == null) {
			clearDialog = new ClearDialog(this);
		}
		clearDialog.setProgramActionContext(programActionContext);
		tool.showDialog(clearDialog);
	}

	/**
	 * Pop up the clear flows dialog
	 */
	private void showClearFlowDialog(ListingActionContext context) {
		if (clearFlowDialog == null) {
			clearFlowDialog = new ClearFlowDialog(this);
		}
		clearFlowDialog.setProgramActionContext(context);
		tool.showDialog(clearFlowDialog);
	}

}
