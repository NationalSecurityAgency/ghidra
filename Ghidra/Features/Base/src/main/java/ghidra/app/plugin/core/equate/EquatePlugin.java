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

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import docking.action.*;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.equate.ClearEquateCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.bean.SetEquateDialog;
import ghidra.app.util.bean.SetEquateDialog.SelectionType;
import ghidra.app.util.datatype.ApplyEnumDialog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.CompoundBackgroundCommand;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.task.*;

/**
 * Class to handle setting, removing, and renaming equates in a program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Add, rename, and delete equates",
	description = "This provides actions for adding, renaming, and deleting equates on operand values."
)
//@formatter:on
public class EquatePlugin extends Plugin {
	private final static String GROUP_NAME = "equate";
	private final static String[] SET_MENUPATH = new String[] { "Set Equate..." };
	private final static String[] RENAME_MENUPATH = new String[] { "Rename Equate..." };
	private final static String[] REMOVE_MENUPATH = new String[] { "Remove Equate" };
	private final static String[] APPLYENUM_MENUPATH = new String[] { "Apply Enum..." };

	// plugin instance variables
	private DockingAction setAction;
	private DockingAction renameAction;
	private DockingAction removeAction;
	private DockingAction applyEnumAction;
	private SetEquateDialog setEquateDialog;
	private ApplyEnumDialog applyEnumDialog;

	public EquatePlugin(PluginTool tool) {
		super(tool);
		createActions();
	}

	/*
	 * Returns the GUI for the {@link SetEquateDialog}.  Note that this function will close
	 * any instance of the dialog that is currently open and construct a new one.
	 */
	private SetEquateDialog createEquateDialog(ListingActionContext context, Scalar scalar) {
		if (setEquateDialog != null) {
			setEquateDialog.close();
		}

		InitializeDialogTask task = new InitializeDialogTask(context.getProgram(), scalar);
		TaskLauncher.launch(task);

		setEquateDialog = task.getDialog();
		setEquateDialog.setHelpLocation(new HelpLocation(getName(), "Set_Equate"));
		return setEquateDialog;
	}

	/*
	 * Returns the GUI for the {@link DataTypeSelectionDialog}. Note that this function will
	 * close any instance of the dialog that is currently open and construct a new one.
	 */
	private ApplyEnumDialog applyEnumDialog(ListingActionContext context) {
		DataTypeManager dtm = context.getProgram().getDataTypeManager();
		if (applyEnumDialog != null) {
			applyEnumDialog.close();
		}
		applyEnumDialog = new ApplyEnumDialog(tool, dtm);
		applyEnumDialog.setHelpLocation(new HelpLocation(getName(), "Apply_Enum"));
		tool.showDialog(applyEnumDialog);
		return applyEnumDialog;
	}

	private void dispose(SetEquateDialog dialog) {
		if (setEquateDialog == dialog) {
			setEquateDialog.dispose();
			setEquateDialog = null;
		}
	}

	/**
	 * Determine if a Set Equate operation is permitted for the specified action context.
	 * The current context must satisfy the following constraints:
	 * <ul>
	 * <li>Current location must correspond to an operand scalar within the default
	 * representation.</li>
	 * <li>If an equate reference on the operand exists it must
	 * correspond to the same value</li>
	 * <li>For data, it must be a simple defined data unit not contained within an
	 * array or composite (CreateEquateCmd does not currently support such data cases)</li>
	 * </ul>
	 * Currently markup of equates is not supported within composite or array data
	 * @param context the action context
	 * @return true if current location satisfies the above constraints
	 */
	protected boolean isEquatePermitted(ListingActionContext context) {

		// Is the data a scalar object.
		Scalar scalar = getScalar(context);
		if (scalar == null) {
			return false;
		}

		// Is the data defined.
		CodeUnit cu = getCodeUnit(context);
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (!data.isDefined()) {
				return false;
			}
			DataType dataType = data.getBaseDataType();
			if (!(dataType instanceof AbstractIntegerDataType)) {
				return false;
			}
		}

		Equate equate = getEquate(context);
		if (equate == null) {
			return true;
		}
		return !isEquateEqualScalar(equate, scalar);
	}

	/**
	 * Called in response to the user activating the Set Equate action from the menu.  This will
	 * ultimately create the background tasks that will create the proper equate(s) for
	 * the selected addresses.
	 *
	 * @param context the action context
	 */
	private void setEquate(ListingActionContext context) {

		// Get the scalar item that was selected.  If this returns null, then something
		// invalid was selected, so exit.
		Scalar curScalar = getScalar(context);
		if (curScalar == null) {
			return;
		}

		// Create the dialog that will allow the user to select options.
		createEquateDialog(context, curScalar);

		// Set the state of the some buttons on the dialog.  ie: if the user has selected
		// a range of addresses we should automatically set the "selection" radio button
		// to the selected state.
		setEquateDialog.setHasSelection(context);

		// If the user has selected the cancel button, exit.
		if (setEquateDialog.showSetDialog() == SetEquateDialog.CANCELED) {
			return;
		}

		// Define an iterator for the task.  We're using a CodeUnitIterator to make sure we inspect
		// all Data and Instruction instances.
		CodeUnitIterator iter = null;

		// Get the program listing.  This is what allows us to get an iterator for the
		// addresses we're interested in.
		Listing listing = context.getProgram().getListing();

		// Now we have to 'populate' the iterator with the proper addresses.  Once we have the
		// iterator, we'll create a background task to process them.
		//
		SelectionType selectionType = setEquateDialog.getSelectionType();

		if (selectionType == SelectionType.CURRENT_ADDRESS) {
			AddressSet addrSet = new AddressSet(context.getAddress());
			iter = listing.getCodeUnits(addrSet, false);
		}

		else if (selectionType == SelectionType.SELECTION) {
			iter = listing.getCodeUnits(context.getSelection(), true);
		}

		else if (selectionType == SelectionType.ENTIRE_PROGRAM) {
			iter = listing.getCodeUnits(context.getProgram().getMemory(), true);
		}

		BackgroundCommand cmd;
		if (setEquateDialog.getEnumDataType() != null) {
			// Now set up a command to run in the background, and execute the task.
			cmd = new CreateEquateCmd(curScalar, iter, setEquateDialog.getEnumDataType(),
				setEquateDialog.getOverwriteExisting(), context);
		}
		else {
			// Now set up a command to run in the background, and execute the task.
			cmd = new CreateEquateCmd(curScalar, iter, setEquateDialog.getEquateName(),
				setEquateDialog.getOverwriteExisting(), context);
		}
		tool.executeBackgroundCommand(cmd, context.getProgram());

		// Finally, blow away the dialog.
		dispose(setEquateDialog);
	}

	/**
	 * Called in response to the user selecting the Apply Enum action from the popup menu. This
	 * action will apply enum values to scalars in a selection.
	 * @param context the action context
	 */
	private void applyEnum(ListingActionContext context) {
		applyEnumDialog = applyEnumDialog(context);
		DataType dataType = applyEnumDialog.getUserChosenDataType();

		if (dataType == null) {
			return;
		}
		if (!(dataType instanceof Enum)) {
			Msg.showError(this, null, "Input Error", "Data Type must be an enum");
			return;
		}

		boolean shouldDoOnSubOps = applyEnumDialog.shouldApplyOnSubOps();

		AddressSetView addresses = context.getSelection();
		if (addresses.isEmpty()) {
			addresses = new AddressSet(context.getAddress());
		}
		Program program = context.getProgram();
		CreateEnumEquateCommand cmd =
			new CreateEnumEquateCommand(program, addresses, (Enum) dataType, shouldDoOnSubOps);
		tool.executeBackgroundCommand(cmd, program);
	}

	/**
	 * Called in response to the user activating rename action from the context menu.
	 *
	 * @param context the action context
	 */
	private void renameEquate(ListingActionContext context) {

		// Get the scalar item that was selected.  If this returns null, then something
		// invalid was selected, so exit.
		Scalar curScalar = getScalar(context);
		if (curScalar == null) {
			return;
		}

		// Now get the equate (one should exist) for this item.  If one doesn't exist, it shouldn't
		// even be an option on the context menu.
		Equate equate = getEquate(context);
		Listing listing = context.getProgram().getListing();

		// Create the dialog that will allow the user to select options.
		createEquateDialog(context, curScalar);

		// Set the state of the some buttons on the dialog.  ie: if the user has selected
		// a range of addresses we should automatically set the "selection" radio button
		// to the selected state.
		setEquateDialog.setHasSelection(context);

		// Check for user-cancel action.
		int result = setEquateDialog.showRenameDialog();
		if (result == SetEquateDialog.CANCELED) {
			return;
		}

		// Retrieve the name we want to change the equate(s) to.  If the name is null,
		// it means it's not a name that's already in the table, so just remove the
		// equate.
		String equateName = setEquateDialog.getEquateName();

		// Define an iterator for the task.  We're using a CodeUnitIterator to make sure we inspect
		// all Data and Instruction instances.
		CodeUnitIterator iter = null;

		SelectionType selectionType = setEquateDialog.getSelectionType();

		if (selectionType == SelectionType.CURRENT_ADDRESS) {
			AddressSet addrSet = new AddressSet(context.getAddress());
			iter = listing.getCodeUnits(addrSet, false);
		}

		else if (selectionType == SelectionType.SELECTION) {
			iter = listing.getCodeUnits(context.getSelection(), true);
		}

		else if (selectionType == SelectionType.ENTIRE_PROGRAM) {
			iter = listing.getCodeUnits(context.getProgram().getMemory(), true);
		}

		// Determine if this is a remove or rename. If the user has left the "new equate name" field
		// blank in the dialog, then remove the equate entirely.
		if (equateName == null) {
			removeEquateOverRange(context, equate, iter);
		}
		else {
			renameEquate(context, equate, equateName, iter);
		}

		// Destroy the dialog.
		dispose(setEquateDialog);
	}

	private Equate getEquate(ListingActionContext context) {
		EquateTable equateTable = context.getProgram().getEquateTable();
		Scalar s = getScalar(context);
		if (s == null) {
			return null;
		}
		return equateTable.getEquate(context.getAddress(), getOperandIndex(context), s.getValue());
	}

	private void renameEquate(ListingActionContext context, Equate oldEquate, String newEquateName,
			CodeUnitIterator iter) {

		// First do a sanity check to make sure we're not trying to change to a duplicate
		// name.
		String oldEquateName = oldEquate.getName();
		if (oldEquateName.equals(newEquateName)) {
			return;
		}

		// Set up a background task that we'll populate with all the rename tasks we need
		// to perform.
		CompoundBackgroundCommand bckCmd =
			new CompoundBackgroundCommand("Rename Equates in Selection", false, true);

		// Now loop over all the code units and search for matching scalars...
		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			renameEquateForCodeUnit(context, oldEquate, newEquateName, oldEquateName, bckCmd, cu);
		}

		// Finally, execute all the rename tasks.
		tool.executeBackgroundCommand(bckCmd, context.getProgram());
	}

	private void renameEquateForCodeUnit(ListingActionContext context, Equate equate,
			String newName, String oldName, CompoundBackgroundCommand bgCmd, CodeUnit cu) {

		if (cu instanceof Instruction) {

			Instruction inst = (Instruction) cu;
			Program program = context.getProgram();
			List<Integer> opIndices = getInstructionMatches(program, inst, equate);
			Address addr = inst.getAddress();
			for (Integer opIndice : opIndices) {
				bgCmd.add(createRenameCmd(oldName, newName, addr, opIndice));
			}
		}
		else if (cu instanceof Data) {

			Data data = (Data) cu;
			if (isDataMatch(data, context, equate)) {
				Address addr = data.getAddress();
				bgCmd.add(createRenameCmd(oldName, newName, addr, getOperandIndex(context)));
			}
		}
	}

	private RenameEquateCmd createRenameCmd(String oldName, String newName, Address addr,
			int opIndex) {

		Enum enoom = getEnumDataType();
		if (enoom != null) {
			return new RenameEquateCmd(oldName, enoom, addr, opIndex);
		}

		return new RenameEquateCmd(oldName, newName, addr, opIndex);
	}

	public Enum getEnumDataType() {
		return setEquateDialog.getEnumDataType();
	}

	private void removeEquateOverRange(ListingActionContext context, Equate equate,
			CodeUnitIterator iter) {

		// Create a background task to process all the remove tasks.
		CompoundBackgroundCommand bckCmd =
			new CompoundBackgroundCommand("Remove Equates in Selection", false, true);

		// Now iterate over all code units in the iterator.
		while (iter.hasNext()) {
			CodeUnit cu = iter.next();
			removeEquateForCodeUnit(context, equate, bckCmd, cu);
		}

		// Finally, execute all the tasks.
		tool.executeBackgroundCommand(bckCmd, context.getProgram());
	}

	private void removeEquateForCodeUnit(ListingActionContext context, Equate equate,
			CompoundBackgroundCommand bckCmd, CodeUnit cu) {
		// A code unit can be either an instruction or data; we need to handle each
		// separately.
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;

			Program program = context.getProgram();
			List<Integer> opIndexes = getInstructionMatches(program, instr, equate);
			for (Integer opIndexe : opIndexes) {
				bckCmd.add(
					new ClearEquateCmd(equate.getName(), instr.getAddress(), opIndexe));
			}
		}
		else if (cu instanceof Data) {
			Data data = (Data) cu;

			if (isDataMatch(data, context, equate)) {
				bckCmd.add(new ClearEquateCmd(equate.getName(), data.getAddress(),
					getOperandIndex(context)));
			}
		}
	}

	private List<Integer> getInstructionMatches(Program program, Instruction instruction,
			Equate equate) {

		// Return list.
		List<Integer> matches = new ArrayList<>();

		// Find out how many operands are listed.
		int numOperands = instruction.getNumOperands();

		for (int opIndex = 0; opIndex <= numOperands; opIndex++) {

			Object[] opObjs = instruction.getOpObjects(opIndex);
			for (Object opObj : opObjs) {

				// Checks to see if the current value is a scalar value
				if (opObj instanceof Scalar) {
					Scalar scalar = (Scalar) opObj;

					// Checks to see if the scalar value is equal to the value
					// we are searching for, AND that it has the same equate name
					// we're trying to rename.
					EquateTable equateTable = program.getEquateTable();
					Address address = instruction.getAddress();
					List<Equate> equates = equateTable.getEquates(address, opIndex);
					for (Equate eq : equates) {
						if (eq.getName().equals(equate.getName()) &&
							isEquateEqualScalar(equate, scalar)) {
							matches.add(opIndex);
						}
					}
				}
			}
		}

		return matches;
	}

	private boolean isDataMatch(Data data, ListingActionContext context, Equate equate) {

		if (!data.isDefined()) {
			return false;
		}

		// First make sure the data is defined - otherwise we don't know what to do with it.
		Object val = data.getValue();
		if (val == null || !(val instanceof Scalar)) {
			return false;
		}

		Scalar scalar = (Scalar) val;
		int opIndex = getOperandIndex(context);

		// Check to see if the scalar value is equal to the value we are searching for, AND
		// that it has the same equate name we're trying to rename.
		Program program = context.getProgram();
		EquateTable equateTable = program.getEquateTable();
		Address address = data.getAddress();
		List<Equate> equates = equateTable.getEquates(address, opIndex);
		for (Equate eq : equates) {
			if (eq.getName().equals(equate.getName()) && isEquateEqualScalar(equate, scalar)) {
				return true;
			}
		}

		return false;
	}

	/*
	 * Removes equates within the selected region, or a single equate if there's
	 * no selection.  The user will be prompted for confirmation before
	 * removing multiple equates in a selection.
	 */
	private void removeSelectedEquates(ListingActionContext context) {

		// First, get the equate for this change.
		Equate equate = getEquate(context);

		// Now get an iterator for the selected region (or the single address if that's
		// the case
		CodeUnitIterator iter = null;

		// Get the selected region.  If this is null, then we're just operating on a single address,
		// which is fine.
		ProgramSelection selection = context.getSelection();

		// Show a confirmation dialog to make sure the user knows they're going to be removing
		// all equates within the selection that match the selected equate.
		if (!selection.isEmpty()) {

			String title = "Remove Equate?";
			String msg = "This will remove all equates with the name " + "'" +
				equate.getDisplayName() + "' in the selection.";

			int option = OptionDialog.showOptionDialog(this.getTool().getActiveWindow(), title, msg,
				"Remove", OptionDialog.QUESTION_MESSAGE);

			if (option == OptionDialog.CANCEL_OPTION) {
				return;
			}
			iter = context.getProgram().getListing().getCodeUnits(context.getSelection(), true);
		}
		else {
			AddressSet addrSet = new AddressSet(context.getAddress());
			iter = context.getProgram().getListing().getCodeUnits(addrSet, false);
		}

		// Call the function that will create the background tasks to process the equate removal.
		removeEquateOverRange(context, equate, iter);
	}

	/**
	 * Get the instruction at the location provided by the context
	 * @param context the action context
	 * @return code unit containing current location if found (component data unsupported)
	 */
	CodeUnit getCodeUnit(ListingActionContext context) {
		Address address = context.getAddress();
		if (address != null) {
			return context.getProgram().getListing().getCodeUnitContaining(address);
		}
		return null;
	}

	/**
	 * Get the operand index at the location
	 * @param context the action context
	 * @return 0-3 for a good operand location, -1 otherwise
	 */
	int getOperandIndex(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			return ((OperandFieldLocation) location).getOperandIndex();
		}
		return -1;
	}

	int getSubOperandIndex(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof OperandFieldLocation) {
			return ((OperandFieldLocation) location).getSubOperandIndex();
		}
		return -1;
	}

	Scalar getScalar(ListingActionContext context) {
		CodeUnit cu = getCodeUnit(context);
		Scalar scalar = getScalar(cu, context);
		return scalar;
	}

	private Scalar getScalar(CodeUnit cu, ListingActionContext context) {
		int opIndex = getOperandIndex(context);
		int subOpIndex = getSubOperandIndex(context);
		Scalar scalar = getScalar(cu, opIndex, subOpIndex);
		return scalar;
	}

	/**
	 * Get scalar value associated with the specified code unit,
	 * opIndex and subOpindex.  NOTE: this method does not support
	 * composite or array data (null will always be returned).
	 * @param cu code unit
	 * @param opIndex operand index
	 * @param subOpIndex sub-operand index
	 * @return scalar value or null
	 */
	private Scalar getScalar(CodeUnit cu, int opIndex, int subOpIndex) {
		if (cu == null) {
			return null;
		}

		if (cu instanceof Data) {
			return cu.getScalar(opIndex);
		}

		if (subOpIndex < 0) {
			return null;
		}

		Instruction instruction = ((Instruction) cu);
		List<?> list = instruction.getDefaultOperandRepresentationList(opIndex);
		if (list == null) {
			return null;
		}

		int numSubOps = list.size();
		Scalar currentScalar = null;

		// Check from opIndex to End for scalar.
		for (int repIndex = subOpIndex; repIndex < numSubOps; repIndex++) {
			Object object = list.get(repIndex);
			if (object instanceof Scalar) {
				currentScalar = (Scalar) object;
				break;
			}
		}
		if (currentScalar == null) {
			for (int repIndex = subOpIndex - 1; repIndex >= 0; repIndex--) {
				Object object = list.get(repIndex);
				if (object instanceof Scalar) {
					currentScalar = (Scalar) object;
					break;
				}
			}
		}
		if (currentScalar == null) {
			return null;
		}

		// Only return scalar if we can find matching scalar in OpObjects
		Object[] opObjects = instruction.getOpObjects(opIndex);
		for (Object object : opObjects) {
			if (object instanceof Scalar && currentScalar.equals(object)) {
				return currentScalar;
			}
		}
		return null;
	}

	/**
	 * Create the action objects for this plugin.
	 */
	private void createActions() {

		tool.setMenuGroup(new String[] { "Convert" }, GROUP_NAME);

		tool.addAction(new ConvertToUnsignedHexAction(this));
		tool.addAction(new ConvertToUnsignedDecimalAction(this));
		tool.addAction(new ConvertToOctalAction(this));
		tool.addAction(new ConvertToSignedHexAction(this));
		tool.addAction(new ConvertToSignedDecimalAction(this));
		tool.addAction(new ConvertToCharAction(this));
		tool.addAction(new ConvertToBinaryAction(this));
		tool.addAction(new ConvertToFloatAction(this));
		tool.addAction(new ConvertToDoubleAction(this));

		setAction = new ListingContextAction("Set Equate", getName()) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				setEquate(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return isEquatePermitted(context);
			}
		};
		setAction.setPopupMenuData(new MenuData(SET_MENUPATH, null, GROUP_NAME));
		setAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_E, 0));

		renameAction = new ListingContextAction("Rename Equate", getName()) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				renameEquate(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				Scalar scalar = getScalar(context);
				if (scalar == null) {
					return false;
				}

				Equate equate = getEquate(context);
				if (equate == null) {
					return false;
				}
				return isEquateEqualScalar(equate, scalar);
			}
		};
		renameAction.setHelpLocation(new HelpLocation("EquatePlugin", "Set_Equate"));
		renameAction.setPopupMenuData(new MenuData(RENAME_MENUPATH, null, GROUP_NAME));
		renameAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_E, 0));

		removeAction = new ListingContextAction("Remove Equate", getName()) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				removeSelectedEquates(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return getEquate(context) != null;
			}
		};
		removeAction.setPopupMenuData(new MenuData(REMOVE_MENUPATH, null, GROUP_NAME));
		removeAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		applyEnumAction = new ListingContextAction("Apply Enum", getName()) {
			@Override
			protected void actionPerformed(ListingActionContext context) {
				applyEnum(context);
			}

			@Override
			protected boolean isEnabledForContext(ListingActionContext context) {
				return context.hasSelection();
			}
		};
		applyEnumAction.setHelpLocation(new HelpLocation("EquatePlugin", "Apply_Enum"));
		applyEnumAction.setPopupMenuData(new MenuData(APPLYENUM_MENUPATH, null, GROUP_NAME));

		tool.addAction(setAction);
		tool.addAction(renameAction);
		tool.addAction(removeAction);
		tool.addAction(applyEnumAction);
	}

	protected boolean isEquateEqualScalar(Equate equate, Scalar scalar) {
		return (equate.getValue() == scalar.getUnsignedValue() ||
			equate.getValue() == scalar.getSignedValue());
	}

	private class InitializeDialogTask extends Task {

		private SetEquateDialog dialog;
		private Program program;
		private Scalar scalar;

		public InitializeDialogTask(Program program, Scalar scalar) {
			super("Initializing Set Equate Dialog", false, false, true);
			this.program = program;
			this.scalar = scalar;
		}

		@Override
		public void run(TaskMonitor monitor) {
			dialog = Swing.runNow(() -> new SetEquateDialog(tool, program, scalar));
		}

		SetEquateDialog getDialog() {
			return dialog;
		}
	}

}
