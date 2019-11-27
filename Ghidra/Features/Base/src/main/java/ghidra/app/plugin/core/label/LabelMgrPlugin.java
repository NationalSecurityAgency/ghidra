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
package ghidra.app.plugin.core.label;

import docking.action.DockingAction;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.app.util.AddEditDialog;
import ghidra.app.util.EditFieldNameDialog;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;

/**
 * Plugin to add and edit labels.
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Edit Labels",
	description = "This plugin provides actions and dialogs for adding, removing and editing labels in the code browser",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class LabelMgrPlugin extends Plugin {

	private OperandLabelDialog operandDialog;
	private AddEditDialog addEditDialog;
	private EditFieldNameDialog editFieldDialog;

	/**
	 * Constructor
	 *
	 * @param plugintool
	 *            reference to the tool
	 */
	public LabelMgrPlugin(PluginTool tool) {
		super(tool);
		// Setup list of actions
		setupActions();
	}

	/**
	 * Creation of the Label Mgr plugin actions.
	 */
	private void setupActions() {
		DockingAction addLabelAction = new AddLabelAction(this);
		tool.addAction(addLabelAction); // add the plugin action

		DockingAction editLabelAction = new EditLabelAction(this);
		tool.addAction(editLabelAction);

		DockingAction editExternalLabelAction = new EditExternalLabelAction(this);
		tool.addAction(editExternalLabelAction);

		DockingAction removeLabelAction = new RemoveLabelAction(this);
		tool.addAction(removeLabelAction); // add the plugin action

		DockingAction setOperandLabelAction = new SetOperandLabelAction(this);
		tool.addAction(setOperandLabelAction); // add the plugin action

		DockingAction labelHistoryAction = new LabelHistoryAction(tool, getName());
		tool.addAction(labelHistoryAction);

		// Create the Show All History action
		DockingAction allHistoryAction = new AllHistoryAction(tool, getName());
		tool.addAction(allHistoryAction);
	}

	/**
	 * Create the necessary dialogs for this plugin. The dialogs are Name Label
	 * and Choose Alias.
	 */
	AddEditDialog getAddEditDialog() {
		if (addEditDialog == null) {
			addEditDialog = new AddEditDialog("", tool);
		}
		return addEditDialog;
	}

	EditFieldNameDialog getEditFieldDialog() {
		if (editFieldDialog == null) {
			editFieldDialog = new EditFieldNameDialog("", tool);
		}
		return editFieldDialog;
	}

	OperandLabelDialog getOperandLabelDialog() {
		if (operandDialog == null) {
			operandDialog = new OperandLabelDialog(this);
		}
		return operandDialog;
	}

	/**
	 * Removes the label or alias that the cursor is over from the current label
	 * field. If an exception is caught during the removal of the label or
	 * alias, a message is written to the status area.
	 */
	protected void removeLabelCallback(ListingActionContext context) {
		Symbol s = getSymbol(context);
		if (s != null) {
			Command cmd = new DeleteLabelCmd(s.getAddress(), s.getName(), s.getParentNamespace());

			if (!tool.execute(cmd, context.getProgram())) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
		}
	}

	/**
	 * AddLabelAction calls this method when an action occurs. At this point in
	 * time, all we want to do is to display the Add Label Dialog.
	 */
	protected void addLabelCallback(ListingActionContext context) {
		getAddEditDialog().addLabel(context.getAddress(), context.getProgram());
	}

	/**
	 * EditLabelAction calls this method when an action occurs. At this point in
	 * time, all we want to do is to display the Add Label Dialog.
	 */
	void editLabelCallback(ListingActionContext context) {

		Symbol s = getSymbol(context);
		if (s != null) {
			if (s.getSource() == SourceType.DEFAULT && s.getSymbolType() == SymbolType.LABEL) {
				getAddEditDialog().addLabel(s.getAddress(), context.getProgram());
			}
			else {
				getAddEditDialog().editLabel(s, context.getProgram());
			}
			return;
		}

		int[] componentPath = context.getLocation().getComponentPath();
		if (componentPath == null || componentPath.length == 0) {
			// add label if not inside array or composite
			addLabelCallback(context);
			return;
		}

		DataTypeComponent dtComp = getComponent(context);
		if (dtComp != null) {
			if (dtComp.getDataType() == DataType.DEFAULT) {
				Msg.showError(this, tool.getActiveWindow(), "Undefined Field",
					"Field data-type must be set prior to editing field name.");
			}
			else {
				getEditFieldDialog().editField(dtComp, context.getProgram());
			}
		}
	}

	void setOperandLabelCallback(ListingActionContext context) {
		getOperandLabelDialog().setOperandLabel(context);
	}

	Symbol getSymbol(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		if (location instanceof LabelFieldLocation) {
			LabelFieldLocation lfl = (LabelFieldLocation) location;
			return lfl.getSymbol();
		}
		else if (location instanceof OperandFieldLocation) {
			VariableOffset variableOffset = ((OperandFieldLocation) location).getVariableOffset();
			if (variableOffset != null) {
				Variable var = variableOffset.getVariable();
				if (var != null) {
					return var.getSymbol();
				}
			}
			Reference ref = getOperandReference(context);
			if (ref != null) {
				return context.getProgram().getSymbolTable().getSymbol(ref);
			}
		}
		return null;
	}

	private static boolean isInUnion(Data data) {
		for (Data parent = data; parent != null; parent = parent.getParent()) {
			if (parent.getDataType() instanceof Union) {
				return true;
			}
		}
		return false;
	}

	static DataTypeComponent getComponent(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		int[] componentPath = location.getComponentPath();
		if (componentPath == null || componentPath.length == 0) {
			return null;
		}
		Data data = context.getProgram().getListing().getDataContaining(location.getAddress());
		if (data == null || !data.isDefined()) {
			return null;
		}
		DataType dt = data.getDataType();
		DataTypeComponent comp = null;
		for (int element : componentPath) {
			if (!(dt instanceof Composite)) {
				return null;
			}
			comp = ((Composite) dt).getComponent(element);
			dt = comp.getDataType();
		}
		return comp;
	}

	static Data getDataComponent(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		int[] componentPath = location.getComponentPath();
		if (componentPath == null || componentPath.length == 0) {
			return null;
		}
		Data data = context.getProgram().getListing().getDataContaining(location.getAddress());
		if (data == null || !data.isDefined()) {
			return null;
		}
		return data.getComponent(componentPath);
	}

	boolean isOnSymbol(ListingActionContext context) {
		return getSymbol(context) != null;
	}

	boolean isOnFunction(ListingActionContext context) {
		return context.getLocation() instanceof FunctionLocation;
	}

	boolean isOnVariableReference(ListingActionContext context) {
		Symbol s = getSymbol(context);
		if (s == null) {
			return false;
		}
		SymbolType type = s.getSymbolType();
		return type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR;
	}

	boolean isOnExternalReference(ListingActionContext context) {
		Symbol s = getSymbol(context);
		if (s == null) {
			return false;
		}
		return s.isExternal();
	}

	/**
	 * Return true if the given context has label history.
	 *
	 * @param contextObj
	 * @return
	 */
	boolean hasLabelHistory(ListingActionContext context) {
		ProgramLocation location = context.getLocation();
		Address addr = null;
		if (location instanceof CodeUnitLocation) {
			CodeUnitLocation loc = (CodeUnitLocation) location;
			addr = loc.getAddress();
		}
		else if (location instanceof OperandFieldLocation) {
			Address a = ((OperandFieldLocation) location).getRefAddress();
			addr = (a == null) ? addr : a;
		}

		SymbolTable st = context.getProgram().getSymbolTable();
		return st.hasLabelHistory(addr);
	}

	private Reference getOperandReference(ListingActionContext context) {
		if (!(context.getLocation() instanceof OperandFieldLocation)) {
			return null;
		}
		OperandFieldLocation opLoc = (OperandFieldLocation) context.getLocation();
		Address address = opLoc.getAddress();
		int opIndex = opLoc.getOperandIndex();

		Data dataComp = getDataComponent(context);
		if (dataComp != null) {
			if (isInUnion(dataComp)) {
				return null;
			}
			address = dataComp.getMinAddress();
		}

		ReferenceManager refMgr = context.getProgram().getReferenceManager();
		//SymbolTable st = currentProgram.getSymbolTable();

		return refMgr.getPrimaryReferenceFrom(address, opIndex);
	}

}
