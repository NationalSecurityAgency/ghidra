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
package ghidra.app.plugin.core.function;

import java.util.*;

import docking.action.DockingAction;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.SetReturnDataTypeCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.app.util.AddEditDialog;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.SwingUpdateManager;

/**
 * The FunctionPlugin allows creation of a function from the current selection.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Add/Remove/Edit Functions",
	description = "Provides the actions for creating, editing, and deleting functions " +
			"and the variables in them.  Users can change the signature, return type," +
			"variable names, variable datatypes and comments.",
	servicesRequired = { ProgramManager.class, DataTypeManagerService.class },
	servicesProvided = { DataService.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class FunctionPlugin extends Plugin implements DataService {
	final static DataType POINTER_DATA_TYPE = new PointerDataType();

	public final static String FUNCTION_MENU_SUBGROUP = "Function";
	public final static String THUNK_FUNCTION_MENU_SUBGROUP = "FunctionThunk";
	public final static String FUNCTION_MENU_PULLRIGHT = "Function";

	public final static String VARIABLE_MENU_SUBGROUP = "FunctionVariable";
	public final static String VARIABLE_MENU_PULLRIGHT = "Function Variables";

//	public final static String SIGNATURE_MENU_SUBGROUP = "FunctionSignature";
//	public final static String SIGNATURE_MENU_PULLRIGHT = "Function Signature";

	public final static String FUNCTION_SUBGROUP_BEGINNING = "A_Beginning";
	public final static String FUNCTION_SUBGROUP_MIDDLE = "M_Middle";

	public static final String SET_DATA_TYPE_PULLRIGHT = "Set Data Type";

	public final static String STACK_MENU_SUBGROUP = "Stack";

	private final static String SET_DATA_TYPE_MENU_PATH = "Set DataType";
	final static String SET_RETURN_TYPE_MENU_PATH = "Set Return Type";
	private final static String SET_PARAMETER_TYPE_MENU_PATH = "Set Parameter Type";

	private CreateFunctionAction createFunctionAction;
	private CreateExternalFunctionAction createExternalFunctionAction;
	private CreateMultipleFunctionsAction createMultipleFunctionsAction;
	private CreateFunctionAction recreateFunctionAction;
	private CreateFunctionAction thunkFunctionAction;
	private EditThunkFunctionAction editThunkFunctionAction;
	private RevertThunkFunctionAction revertThunkFunctionAction;
	private ClearFunctionAction clearFunctionReturnValueAction;
	private ClearFunctionAction clearVariableDataTypeAction;
	private ClearFunctionAction clearFunctionParamterDataTypeAction;
//	private EditFunctionSymbolSignatureAction editFunctionSymbolSignatureAction;
	private CreateFunctionDefinitionAction createFunctionDefAction;
	private DeleteFunctionAction deleteFunctionAction;
	private VariableCommentAction variableCommentAction;
	private VariableCommentDeleteAction variableCommentDeleteAction;
	private EditNameAction editFunctionNameAction;
	private EditNameAction editVariableNameAction;
	private EditOperandNameAction editOperandNameAction;
	private VariableDeleteAction variableDeleteAction;
	private EditStructureAction editStructureAction;
	private RecentlyUsedAction recentlyUsedAction;
	private DataAction voidAction;
	private DataAction pointerAction;
	private CreateArrayAction arrayAction;
	private AnalyzeStackRefsAction analyzeStackRefsAction;
	private EditFunctionPurgeAction editFunctionPurgeAction;
//	private AddVarArgsAction addVarArgsAction;
//	private DeleteVarArgsAction deleteVarArgsAction;
	private ChooseDataTypeAction chooseDataTypeAction;
	private SetStackDepthChangeAction setStackDepthChangeAction;
	private RemoveStackDepthChangeAction removeStackDepthChangeAction;

	private DataTypeManagerService dtmService;
	private List<DataAction> favoriteActions = new ArrayList<>();
	private List<CycleGroupAction> cgActions = new ArrayList<>();

	private AddEditDialog functionNameDialog;
	private AddEditDialog variableNameDialog;
	private VariableCommentDialog variableCommentDialog;
	private DataTypeManagerChangeListenerAdapter adapter;
	private EditFunctionAction editFunctionAction;

	private SwingUpdateManager favoritesUpdateManager;

	public FunctionPlugin(PluginTool tool) {
		super(tool);
		createActions();
		favoritesUpdateManager = new SwingUpdateManager(1000, 30000, () -> updateFavoriteActions());
	}

	@Override
	protected void init() {
		initializeServices();
		addCycleGroupActions();
		updateFavoriteActions();

	}

	@Override
	public void dispose() {
		favoritesUpdateManager.dispose();

		if (dtmService != null) {
			dtmService.removeDataTypeManagerChangeListener(adapter);
		}
		super.dispose();
		if (functionNameDialog != null) {
			functionNameDialog.close();
			functionNameDialog = null;
		}
		if (variableNameDialog != null) {
			variableNameDialog.close();
			variableNameDialog = null;
		}
		if (variableCommentDialog != null) {
			variableCommentDialog.close();
			variableCommentDialog = null;
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent) {
			favoritesUpdateManager.updateLater();
		}
	}

	/**
	 * Add the cycle group actions
	 */
	private void addCycleGroupActions() {
		for (int i = 0; i < cgActions.size(); i++) {
			DockingAction action = cgActions.get(i);
			tool.removeAction(action);
		}
		cgActions.clear();

		for (CycleGroup group : CycleGroup.ALL_CYCLE_GROUPS) {
			CycleGroupAction action = new CycleGroupAction(group, this);
			tool.addAction(action);
			cgActions.add(action);
		}
	}

	/**
	 * Initialize services used
	 */
	private void initializeServices() {
		dtmService = tool.getService(DataTypeManagerService.class);
		adapter = new DataTypeManagerChangeListenerAdapter() {
			@Override
			public void favoritesChanged(DataTypeManager dtm, DataTypePath path,
					boolean isFavorite) {
				favoritesUpdateManager.update();
			}
		};
		dtmService.addDataTypeManagerChangeListener(adapter);
	}

	/**
	 * Set up Actions
	 */
	private void createActions() {
		recentlyUsedAction = new RecentlyUsedAction(this);

		recentlyUsedAction.setEnabled(false);

		tool.addAction(recentlyUsedAction);

		// we want to put all function pull-right menus in the same group
		tool.setMenuGroup(new String[] { FUNCTION_MENU_PULLRIGHT }, FUNCTION_MENU_SUBGROUP,
			FUNCTION_SUBGROUP_MIDDLE);
		//tool.setMenuGroup(new String[] { SIGNATURE_MENU_PULLRIGHT }, FUNCTION_MENU_SUBGROUP);
		tool.setMenuGroup(new String[] { VARIABLE_MENU_PULLRIGHT }, FUNCTION_MENU_SUBGROUP);
		tool.setMenuGroup(new String[] { SET_DATA_TYPE_PULLRIGHT }, FUNCTION_MENU_SUBGROUP);

		// Non-menu actions

		clearFunctionReturnValueAction = new ClearFunctionAction("Clear Function Return Type", this,
			FunctionReturnTypeFieldLocation.class);
		tool.addAction(clearFunctionReturnValueAction);

		editFunctionAction = new EditFunctionAction(this);
		tool.addAction(editFunctionAction);

		clearVariableDataTypeAction =
			new ClearFunctionAction("Clear Variable Data Type", this, VariableLocation.class);
		tool.addAction(clearVariableDataTypeAction);

		clearFunctionParamterDataTypeAction = new ClearFunctionAction("Clear Parameter Data Type",
			this, FunctionParameterFieldLocation.class);
		tool.addAction(clearFunctionParamterDataTypeAction);

		// Function menu group

		createFunctionAction = new CreateFunctionAction("Create Function", this);
		tool.addAction(createFunctionAction);

		createExternalFunctionAction =
			new CreateExternalFunctionAction("Create External Function", this);
		tool.addAction(createExternalFunctionAction);

		createMultipleFunctionsAction =
			new CreateMultipleFunctionsAction("Create Multiple Functions", this);
		tool.addAction(createMultipleFunctionsAction);

		recreateFunctionAction = new CreateFunctionAction("Re-create Function", this, true, false);
		tool.addAction(recreateFunctionAction);

		thunkFunctionAction = new CreateFunctionAction("Create Thunk Function", this, false, true);
		tool.addAction(thunkFunctionAction);

		editThunkFunctionAction = new EditThunkFunctionAction(this);
		tool.addAction(editThunkFunctionAction);

		revertThunkFunctionAction = new RevertThunkFunctionAction(this);
		tool.addAction(revertThunkFunctionAction);

//		editFunctionSymbolSignatureAction = new EditFunctionSymbolSignatureAction(this);
//		tool.addAction(editFunctionSymbolSignatureAction);

		createFunctionDefAction = new CreateFunctionDefinitionAction(this);
		tool.addAction(createFunctionDefAction);

		deleteFunctionAction = new DeleteFunctionAction(this);
		tool.addAction(deleteFunctionAction);

		editOperandNameAction = new EditOperandNameAction(this);
		tool.addAction(editOperandNameAction);

		editFunctionNameAction = new EditNameAction(true, this);
		tool.addAction(editFunctionNameAction);

		analyzeStackRefsAction = new AnalyzeStackRefsAction(this);
		tool.addAction(analyzeStackRefsAction);

		editFunctionPurgeAction = new EditFunctionPurgeAction(this);
		tool.addAction(editFunctionPurgeAction);

		setStackDepthChangeAction = new SetStackDepthChangeAction(this);
		tool.addAction(setStackDepthChangeAction);

		removeStackDepthChangeAction = new RemoveStackDepthChangeAction(this);
		tool.addAction(removeStackDepthChangeAction);

//		addVarArgsAction = new AddVarArgsAction(this);
//		tool.addAction(addVarArgsAction);

//		deleteVarArgsAction = new DeleteVarArgsAction(this);
//		tool.addAction(deleteVarArgsAction);

		// Variable menu group

		editVariableNameAction = new EditNameAction(false, this);
		tool.addAction(editVariableNameAction);

		variableDeleteAction = new VariableDeleteAction(this);
		tool.addAction(variableDeleteAction);

		variableCommentAction = new VariableCommentAction(this);
		tool.addAction(variableCommentAction);

		variableCommentDeleteAction = new VariableCommentDeleteAction(this);
		tool.addAction(variableCommentDeleteAction);

		// Data-type menu pull-right actions
		voidAction = new VoidDataAction(this);
		tool.addAction(voidAction);

		pointerAction = new PointerDataAction(this);
		tool.addAction(pointerAction);

		arrayAction = new CreateArrayAction(this);
		tool.addAction(arrayAction);

		editStructureAction = new EditStructureAction(this);
		tool.addAction(editStructureAction);

		chooseDataTypeAction = new ChooseDataTypeAction(this);
		tool.addAction(chooseDataTypeAction);
	}

	int getMaxVariableSize(ListingActionContext context) {
		int maxSize = Integer.MAX_VALUE;
		ProgramLocation location = context.getLocation();
		if (location instanceof VariableLocation) {
			VariableLocation varLoc = (VariableLocation) location;
			Variable var = varLoc.getVariable();
			if (var.isStackVariable()) {
				Function fun = getFunction(context);
				int size = getMaxStackVariableSize(fun, var);
				maxSize = size < 0 ? Integer.MAX_VALUE : size;
			}
		}
		return maxSize;
	}

	protected void execute(Program program, Command cmd) {
		if (!tool.execute(cmd, program)) {
			Msg.showError(this, tool.getToolFrame(), cmd.getName(), cmd.getStatusMsg());
		}
	}

	protected void execute(Program program, BackgroundCommand cmd) {
		tool.executeBackgroundCommand(cmd, program);
	}

	boolean isValidDataLocation(ProgramLocation location) {

		if (!(location instanceof FunctionSignatureFieldLocation)) {
			return false;
		}

		if (location instanceof FunctionThunkFieldLocation ||
			location instanceof FunctionCallingConventionFieldLocation ||
			location instanceof FunctionInlineFieldLocation ||
			location instanceof FunctionNameFieldLocation ||
			location instanceof FunctionNoReturnFieldLocation ||
			location instanceof FunctionInlineFieldLocation) {

			// these locations don't have types
			return false;
		}

		return true;
	}

	String getDataActionMenuName(ProgramLocation location) {
		if (location instanceof FunctionParameterFieldLocation) {
			return SET_PARAMETER_TYPE_MENU_PATH;
		}
		if (location instanceof FunctionReturnTypeFieldLocation) {
			return SET_RETURN_TYPE_MENU_PATH;
		}
		return SET_DATA_TYPE_MENU_PATH;
	}

	/**
	 * Get an iterator over all functions overlapping the current selection.
	 * If there is no selection any functions overlapping the current location.
	 * 
	 * @param context the context 
	 * @return Iterator over functions
	 */
	public Iterator<Function> getFunctions(ListingActionContext context) {
		ProgramSelection selection = context.getSelection();
		Program program = context.getProgram();
		ProgramLocation location = context.getLocation();
		if (selection != null && !selection.isEmpty()) {
			return program.getFunctionManager().getFunctionsOverlapping(selection);
		}
		if (location != null) {
			Address loc = location.getAddress();
			return program.getFunctionManager().getFunctionsOverlapping(new AddressSet(loc, loc));
		}
		return Collections.emptyIterator();
	}

	Function getFunction(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		Address entry;
		if (loc instanceof FunctionLocation) {
			entry = ((FunctionLocation) loc).getFunctionAddress();
		}
		else {
			entry = context.getAddress();
		}
		if (entry == null) {
			return null;
		}
		return context.getProgram().getListing().getFunctionAt(entry);
	}

	Function getFunctionInOperandField(Program program, OperandFieldLocation opLoc) {
		if (program == null) {
			return null;
		}
		Address refAddr = opLoc.getRefAddress();
		if (refAddr != null) {
			return program.getFunctionManager().getFunctionAt(refAddr);
		}
		return null;
	}

	@Override
	public boolean isCreateDataAllowed(ListingActionContext context) {
		return (context.getLocation() instanceof FunctionLocation);
	}

	public boolean isCreateFunctionAllowed(ListingActionContext context, boolean allowExisting,
			boolean createThunk) {

		// A program and location is needed for any create function action.
		Program program = context.getProgram();
		if (program == null) {
			return false;
		}

		ProgramLocation location = context.getLocation();
		if (location == null) {
			return false;
		}

		Address addr = location.getAddress();
		if (addr == null) {
			return false;
		}

		boolean cursorIsInSelection = false;
		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty()) {
			//**** NOTE: the minimum address of the selection is used as the entry point
			//****       to the function.  The current cursor location could be used
			//****       as the entry, but that might be confusing
			addr = selection.getMinAddress();
			cursorIsInSelection = true;
		}

		// can't create a function on a function
		Function func = program.getListing().getFunctionAt(addr);
		if ((func == null && !allowExisting) ||
			(func != null && allowExisting && !func.isThunk())) {
			// If we have a selection, don't enable the selection if the cursor is
			// not in the selection.
			if (cursorIsInSelection) {
				return true;
			}
			else if (program.getListing().getInstructionContaining(addr) != null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Lay down the specified dataType on a function return, parameter or local variable
	 * based upon the programActionContext.  Pointer conversion will be handled
	 * by merging the existing dataType with the specified dataType.
	 * @param dt The DataType to create.
	 * @param programActionContext action context
	 * @param enableConflictHandling if true and specified dataType results in a storage conflict,
	 * user may be prompted for removal of conflicting variables (not applicable for return type)
	 */
	@Override
	public boolean createData(DataType dt, ListingActionContext programActionContext,
			boolean enableConflictHandling) {
		return createData(dt, programActionContext, true, enableConflictHandling);
	}

	/**
	 * This method is the same as {@link #createData(DataType, ListingActionContext, boolean)}, 
	 * except that this method will use the given value of <tt>convertPointers</tt> to determine 
	 * if the new DataType should be made into a pointer if the existing DataType is a pointer.
	 * 
	 * @param dataType the DataType to create
	 * @param context the context containing the location at which to create the DataType
	 * @param convertPointers True signals to convert the given DataType to a pointer if there is
	 *        an existing pointer at the specified location.
	 * @param promptForConflictRemoval if true and specified dataType results in a storage conflict,
	 * user may be prompted for removal of conflicting variables (not applicable for return type)
	 * @return True if the DataType could be created at the given location.
	 */
	public boolean createData(DataType dataType, ListingActionContext context,
			boolean convertPointers, boolean promptForConflictRemoval) {
		ProgramLocation location = context.getLocation();
		Program program = context.getProgram();
		if (!(location instanceof FunctionLocation)) {
			tool.setStatusInfo("Unsupported function location for data-type");
			return false;
		}

		if (dataType != DataType.DEFAULT && dataType != DataType.VOID) {
			dtmService.setRecentlyUsed(dataType);
		}

		Function function = getFunction(context);
		if (function == null) {
			tool.setStatusInfo("Unsupported function location for data-type");
			return false;
		}

		// TODO: this will not allow setting a return value as a function pointer
		if ((location instanceof FunctionSignatureFieldLocation) &&
			(dataType instanceof FunctionSignature)) {
			return tool.execute(new ApplyFunctionSignatureCmd(function.getEntryPoint(),
				(FunctionSignature) dataType, SourceType.USER_DEFINED), program);
		}

		DataType existingDT = getCurrentDataType(context);
		dataType = DataUtilities.reconcileAppliedDataType(existingDT, dataType, convertPointers);

		if (dataType.getLength() < 0) {
			tool.setStatusInfo("Only fixed-length data-type permitted");
			return false;
		}

		// this check must come before the signature check, since this is a FunctionSignatureFieldLocation
		if (location instanceof FunctionParameterFieldLocation) {
			FunctionParameterFieldLocation parameterLocation =
				(FunctionParameterFieldLocation) location;
			Parameter parameter = parameterLocation.getParameter();

			return setVariableDataType(parameter, dataType, promptForConflictRemoval);
		}
		else if (location instanceof FunctionSignatureFieldLocation) {
			SourceType source =
				(dataType == DataType.DEFAULT) ? SourceType.DEFAULT : SourceType.USER_DEFINED;
			return tool.execute(
				new SetReturnDataTypeCmd(function.getEntryPoint(), dataType, source), program);
		}
		else if (location instanceof VariableLocation) {
			Variable variable = ((VariableLocation) location).getVariable();
			return setVariableDataType(variable, dataType, promptForConflictRemoval);
		}
		tool.setStatusInfo("Unsupported function location for data-type");
		return false;
	}

	private boolean setVariableDataType(Variable variable, DataType dataType,
			boolean promptForConflictRemoval) {
		String varType = ((variable instanceof Parameter) ? "Parameter" : "Local Variable");
		Program program = variable.getFunction().getProgram();
		int txId = program.startTransaction("Set " + varType + " Data-type");
		try {
			variable.setDataType(dataType, true, false, SourceType.USER_DEFINED);
			tool.setStatusInfo("");
			return true;
		}
		catch (VariableSizeException e) {
			tool.setStatusInfo(e.getMessage());
			if (e.canForce() && promptForConflictRemoval) {
				String msg = varType + " " + variable.getName() + " size change resulted in \n" +
					e.getMessage() + "\n \nDelete conflicting " + varType + "(s)";
				if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialog(tool.getActiveWindow(),
					varType + " Conflict", msg)) {
					tool.setStatusInfo("");
					try {
						variable.setDataType(dataType, true, true, SourceType.USER_DEFINED);
						return true;
					}
					catch (InvalidInputException e1) {
						tool.setStatusInfo(e.getMessage());
					}
				}
			}
		}
		catch (InvalidInputException e) {
			tool.setStatusInfo(e.getMessage());
		}
		finally {
			program.endTransaction(txId, true);
		}
		return false;
	}

	protected DataType getCurrentDataType(ListingActionContext context) {
		Program program = context.getProgram();
		ProgramLocation loc = context.getLocation();
		if (loc instanceof FunctionParameterFieldLocation) {
			Parameter parm = ((FunctionParameterFieldLocation) loc).getParameter();
			return parm.getFormalDataType();
		}
		if (loc instanceof FunctionSignatureFieldLocation) {
			Address funcEntry = ((FunctionSignatureFieldLocation) loc).getFunctionAddress();
			Function fun = program.getFunctionManager().getFunctionAt(funcEntry);
			return fun.getReturn().getFormalDataType();
		}
		if (loc instanceof VariableLocation) {
			Variable var = ((VariableLocation) loc).getVariable();
			if (var instanceof Parameter) {
				return ((Parameter) var).getFormalDataType();
			}
			return var.getDataType();
		}
		return null;
	}

	/**
	 * Return the maximum data type length permitted for the specified local variable.  A -1 
	 * returned value indicates no limit imposed.
	 * 
	 * @param fun the function
	 * @param var the variable
	 * @return maximum data type length permitted for var
	 */
	int getMaxStackVariableSize(Function fun, Variable var) {

		StackFrame frame = fun.getStackFrame();
		Variable[] vars = frame.getStackVariables();
		int offset = var.getStackOffset();
		int fuOffset = var.getFirstUseOffset();
		boolean isParam = var instanceof Parameter;

		if (frame.growsNegative() == !isParam) {
			if (offset >= fun.getStackFrame().getParameterOffset()) {
				throw new IllegalArgumentException("invalid stack offset for variable type");
			}
			for (Variable var2 : vars) {
				Variable v = var2;
				int voff = v.getStackOffset();
				if (voff < 0) {
					if (v.getFirstUseOffset() == fuOffset && voff > offset) {
						if (isParam || !Undefined.isUndefined(v.getDataType())) {
							return voff - offset;
						}
					}
				}
				else {
					break;
				}
			}
			return -offset;
		}

		if (offset < fun.getStackFrame().getParameterOffset()) {
			throw new IllegalArgumentException("invalid stack offset for variable type");
		}

		for (Variable var2 : vars) {
			Variable v = var2;
			int voff = v.getStackOffset();
			if (voff > 0) {
				if (v.getFirstUseOffset() == fuOffset && voff > offset) {
					if (isParam || !Undefined.isUndefined(v.getDataType())) {
						return voff - offset;
					}
				}
			}
		}
		return -1; // No Limit
	}

	/**
	 * Update the Favorites actions for favorite data types.
	 */
	private void updateFavoriteActions() {
		clearActions(favoriteActions);

		// Clear existing actions
		DataAction action = new DataAction(DataType.DEFAULT, this);
		tool.addAction(action);
		favoriteActions.add(action);
		// Add Favorite data actions
		List<DataType> favorites = dtmService.getFavorites();
		for (DataType dataType : favorites) {
			if (dataType.isEquivalent(POINTER_DATA_TYPE) || dataType.isEquivalent(DataType.VOID)) {
				continue;
			}
			action = new DataAction(dataType, this);
			tool.addAction(action);
			favoriteActions.add(action);
		}
	}

	/**
	 * Get rid of the dynamically created list of data types
	 */
	private void clearActions(List<? extends DockingAction> actions) {
		for (DockingAction action : actions) {
			tool.removeAction(action);
			action.dispose();
		}
		actions.clear();
	}

	public VariableCommentDialog getVariableCommentDialog() {
		if (variableCommentDialog == null) {
			variableCommentDialog = new VariableCommentDialog(this);
		}
		return variableCommentDialog;
	}

	public DataTypeManagerService getDataTypeManagerService() {
		return dtmService;
	}

}
