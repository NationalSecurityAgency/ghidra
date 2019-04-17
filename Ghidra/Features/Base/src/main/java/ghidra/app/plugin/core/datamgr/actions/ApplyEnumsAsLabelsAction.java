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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.*;

public class ApplyEnumsAsLabelsAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public ApplyEnumsAsLabelsAction(DataTypeManagerPlugin plugin) {
		super("Create Labels From Enums", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { "Create Labels From Enums" }, null, "VeryLast"));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (isValidNode(node)) {
				return true;
			}
		}
		return false;
	}

	private boolean isValidNode(GTreeNode node) {
		if (node instanceof DataTypeNode) {
			DataType dataType = ((DataTypeNode) node).getDataType();
			if (dataType instanceof ghidra.program.model.data.Enum) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypesActionContext dtActionContext = (DataTypesActionContext) context;
		GTree gTree = (GTree) dtActionContext.getContextObject();
		Program program = dtActionContext.getProgram();
		if (program == null) {
			Msg.showError(this, gTree, "Create Labels From Enums Failed",
				"A suitable program must be open and activated before\n" +
					"create labels from enums may be performed.");
			return;
		}
		ApplySelectedEnumsTask applySelectedEnumsTask = new ApplySelectedEnumsTask(gTree, program);
		new TaskLauncher(applySelectedEnumsTask, gTree);
	}

	private class ApplySelectedEnumsTask extends Task {

		private final Program program;
		private final GTree gTree;

		ApplySelectedEnumsTask(GTree gTree, Program program) {
			super("Create Labels From Selected Enum Data Types", true, false, true);
			this.gTree = gTree;
			this.program = program;
		}

		@Override
		public void run(TaskMonitor monitor) {
			DataTypeManager dataTypeManager = program.getDataTypeManager();
			int totalLabelsCreated = 0;
			boolean someAlreadyExisted = false;
			boolean failedToCreateSome = false;

			int transactionID = -1;
			boolean commit = false;
			try {
				// start a transaction
				transactionID =
					dataTypeManager.startTransaction("Create Labels From Selected Enum Data Types");

				TreePath[] selectionPaths = gTree.getSelectionPaths();
				for (TreePath path : selectionPaths) {
					GTreeNode node = (GTreeNode) path.getLastPathComponent();
					if (!(node instanceof DataTypeNode)) {
						continue;
					}

					DataTypeNode dtNode = (DataTypeNode) node;
					DataType dataType = dtNode.getDataType();
					if (!(dataType instanceof Enum)) {
						continue;
					}

					Enum enumDt = (Enum) dataType;
					CreateLabelResult result = createLabels(enumDt);
					totalLabelsCreated += result.numberCreated;
					someAlreadyExisted |= result.someAlreadyExisted;
					failedToCreateSome |= result.failedToCreateSomeLabels;
				}

				commit = true;
			}
			finally {
				// commit the changes
				dataTypeManager.endTransaction(transactionID, commit);
			}

			if (failedToCreateSome) {
				Msg.showWarn(this, gTree, "Couldn't Create Some Labels",
					"One or more labels couldn't be created from the Enum values." +
						"\nSee user log in system console for more info.");
			}

			//@formatter:off
			String message = (totalLabelsCreated > 0) ?
							 	"Labels created: " + totalLabelsCreated + ".":
							 	"Couldn't create any labels for the selected data types.";
			//@formatter:on
			if (someAlreadyExisted) {
				message += " Some labels already exist.";
			}

			plugin.getTool().setStatusInfo(message);
		}

		private CreateLabelResult createLabels(Enum enumDt) {
			long[] values = enumDt.getValues();
			SymbolTable symbolTable = program.getSymbolTable();
			CreateLabelResult result = new CreateLabelResult();
			for (long value : values) {
				// Check to see if value is an address that exists in the program.
				// If so then create a label there with the enum value's name.
				String labelName = enumDt.getName(value);
				labelName = SymbolUtilities.replaceInvalidChars(labelName, true);
				AddressFactory addressFactory = program.getAddressFactory();
				String addressString = Long.toHexString(value);
				Address address = addressFactory.getAddress(addressString);
				if (address == null) {
					continue;
				}

				Memory memory = program.getMemory();
				if (!memory.contains(address)) {
					Msg.warn(this, "Couldn't create label for \"" + labelName + "\" at " +
						addressString + ".");
					result.failedToCreateSomeLabels = true;
					continue;
				}

				try {
					Symbol symbol = symbolTable.getGlobalSymbol(labelName, address);
					if (symbol == null) {
						symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
						result.numberCreated++;
					}
					else {
						result.someAlreadyExisted = true;
					}
				}
				catch (InvalidInputException e) {
					Msg.warn(this, "Couldn't create label for \"" + labelName + "\" at " +
						addressString + "." + "\n" + e.getMessage());
					result.failedToCreateSomeLabels = true;
				}
			}

			return result;
		}

		private class CreateLabelResult {
			int numberCreated;
			boolean someAlreadyExisted;
			boolean failedToCreateSomeLabels;
		}
	}
}
