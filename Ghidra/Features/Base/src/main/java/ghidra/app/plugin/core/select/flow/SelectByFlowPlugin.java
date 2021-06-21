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
package ghidra.app.plugin.core.select.flow;

import java.util.ArrayList;
import java.util.Iterator;

import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.*;

/**
 * The SelectByFlowPlugin adds selection of code based on program flow to a
 * tool. Selection is based on the initial selection or if there is no selection
 * then on where the cursor is located in the program.<BR>
 * This plugin provides the following types of selection:<BR>
 * <ul>
 * <li>Select by following the flow from the specified address(es) onward.
 * Properties indicate whether or not CALLS or JUMPS should be followed.</li>
 * <li>Select the subroutine(s) for the specified address(es).</li>
 * <li>Select the function(s) for the specified address(es).</li>
 * <li>Select dead subroutine(s) for the specified address(es).</li>
 * <li>Select the current program changes.</li>
 * <li>Select by following the flow to the specified address(es).
 * Properties indicate whether or not CALLS or JUMPS should be followed.</li>
 * </UL>
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Select By Flow",
	description = "This plugin makes a selection in the Code Browser by " +
			"following the execution flow from the current cursor location. " +
			"Options can be set to control what types of execution " +
			"should be followed, e.g., follow computed calls, computed jumps.",
	servicesRequired = { ProgramManager.class, BlockModelService.class },
	eventsProduced = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class SelectByFlowPlugin extends Plugin implements OptionsChangeListener {
	private DockingAction selectAllFlowsFromAction;
	private DockingAction selectLimitedFlowsFromAction;
	private DockingAction selectSubroutineAction;
	private DockingAction selectDeadSubroutineAction;
	private DockingAction selectFunctionAction;
	private DockingAction selectProgramChangesAction;
	private DockingAction selectAllFlowsToAction;
	private DockingAction selectLimitedFlowsToAction;

	public static int SELECT_ALL_FLOWS_FROM = 0;
	public static int SELECT_LIMITED_FLOWS_FROM = 1;
	public static int SELECT_SUBROUTINES = 2;
	public static int SELECT_FUNCTIONS = 3;
	public static int SELECT_DEAD_SUBROUTINES = 4;
	public static int SELECT_ALL_FLOWS_TO = 5;
	public static int SELECT_LIMITED_FLOWS_TO = 6;

	private static final String[] selectionTypes = { "Select All Flows From",
		"Select Limited Flows From", "Select Subroutine", "Select Function",
		"Select Dead Subroutines", "Select All Flows To", "Select Limited Flows To" };

	private boolean followComputedCall = false;
	private boolean followConditionalCall = false;
	private boolean followUnconditionalCall = false;
	private boolean followComputedJump = false;
	private boolean followConditionalJump = true;
	private boolean followUnconditionalJump = true;
	private boolean followPointers = false;

	private BlockModelService blockModelService;

	public SelectByFlowPlugin(PluginTool tool) {

		super(tool);

		// set up list of actions.
		setupActions();
		initializeOptions();
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		HelpLocation help = new HelpLocation(HelpTopics.SELECTION, "SelectByFlowOptions");
		options.setOptionsHelpLocation(help);

		options.registerOption(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, false, help,
			"When a computed call is encountered, determines whether to go to the call's "
				+ "destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, false, help,
			"When a conditional call is encountered, determines whether to go to the call's "
				+ "destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, false, help,
			"When an unconditional call is encountered, determines whether to go to the "
				+ "call's destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, false, help,
			"When a computed jump is encountered, determines whether to go to the jump's "
				+ "destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, true, help,
			"When a conditional jump is encountered, determines whether to go to the jump's "
				+ "destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, true, help,
			"When an unconditional jump is encountered, determines whether to go to the "
				+ "jump's destination and select by flow there too.");

		options.registerOption(GhidraOptions.OPTION_FOLLOW_POINTERS, false, help,
			"When a pointer is encountered, determines whether to go to the address being "
				+ "pointed to and select by flow there too.");

		setOptions(options);
		options.addOptionsChangeListener(this);
	}

	@Override
	protected void init() {
		blockModelService = tool.getService(BlockModelService.class);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		setOptions(options);
	}

	private void setOptions(Options options) {
		followComputedCall = options.getBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_CALL, false);

		followConditionalCall =
			options.getBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_CALL, false);

		followUnconditionalCall =
			options.getBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_CALL, false);

		followComputedJump = options.getBoolean(GhidraOptions.OPTION_FOLLOW_COMPUTED_JUMP, false);

		followConditionalJump =
			options.getBoolean(GhidraOptions.OPTION_FOLLOW_CONDITIONAL_JUMP, true);

		followUnconditionalJump =
			options.getBoolean(GhidraOptions.OPTION_FOLLOW_UNCONDITIONAL_JUMP, true);

		followPointers = options.getBoolean(GhidraOptions.OPTION_FOLLOW_POINTERS, false);
	}

	/**
	 * Initiate a selection task for the specified selection type.
	 * @param selectionType
	 * SELECT_ALL_FLOW indicates all flow types should be followed.
	 * <BR>
	 * SELECT_LIMITED_FLOW indicates the flow types that have their properties set to true 
	 * should be followed and selected.
	 * <BR>
	 * SELECT_SUBROUTINE indicates all code units that are in the subroutine
	 * block(s) containing the specified address(es).
	 * <BR>
	 * SELECT_ALL_FLOWS_TO indicates all flow types should be followed to the current location
	 * or selection.
	 * <BR>
	 * SELECT_LIMITED_FLOWS_TO indicates the flow types that have their properties set to true 
	 * should be followed to the current location or selection.
	 * <BR>
	 */
	void select(NavigatableActionContext context, int selectionType) {
		try {
			SelectByFlowTask task = new SelectByFlowTask(context, selectionType);
			tool.execute(task, 750);
		}
		catch (InvalidInputException e) {
			tool.setStatusInfo(e.getMessage(), true);
		}
	}

	/**
	 * performSelection selects code units by a particular method starting with
	 * the current selection or location in the program.
	 * <BR>When following flow and there is a selection,
	 * then the flow is followed from all the addresses in the selection.
	 * If there isn't a selection, the flow is followed from the current location.
	 * <BR>When selecting subroutines, all addresses for the subroutines that
	 * contain the initial selection or cursor location are selected.
	 * <BR>The selection is changed to all the addresses in the resulting flow or
	 * selected subroutines.
	 * @param monitor a cancellable task monitor, may be null
	 * @param selectionType
	 * SELECT_ALL_FLOW indicates all flow types should be followed.
	 * <BR>
	 * SELECT_LIMITED_FLOW indicates the flow types that have their properties set to true 
	 * should be followed and selected.
	 * <BR>
	 * SELECT_SUBROUTINE indicates all code units that are in the subroutine
	 * block(s) containing the specified address(es).
	 * <BR>
	 * SELECT_ALL_FLOWS_TO indicates all flow types should be followed to the addressSet.
	 * <BR>
	 * SELECT_LIMITED_FLOWS_TO indicates the flow types that have their properties set to true 
	 * should be followed to the addressSet and selected.
	 * <BR>
	 * @param addressSet the initial address set which identifies the starting 
	 * point(s) for computation of a selection.  This set may be modified in the
	 * process of computing a selection.
	 * @see FollowFlow
	 */
	void performSelection(TaskMonitor monitor, NavigatableActionContext context, int selectionType,
			AddressSet addressSet) {
		Program program = context.getProgram();
		AddressSet selectionAddressSet = null;
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		monitor.setMessage("Computing Selection...");

		if (selectionType == SELECT_FUNCTIONS) {
			selectionAddressSet = selectFunctions(monitor, program, addressSet);
		}
		else if (selectionType == SELECT_SUBROUTINES) {
			try {
				selectionAddressSet = selectSubroutines(monitor, program, addressSet);
			}
			catch (CancelledException e) {
				return;
			}
		}
		else if (selectionType == SELECT_DEAD_SUBROUTINES) {
			try {
				selectionAddressSet = selectDeadSubroutines(monitor, program, addressSet);
			}
			catch (CancelledException e) {
				return;
			}
		}
		else if (selectionType == SELECT_LIMITED_FLOWS_TO || selectionType == SELECT_ALL_FLOWS_TO) {
			FlowType[] doNotFollowTypes = null; // Default is Follow All Flows To.
			if (selectionType == SELECT_LIMITED_FLOWS_TO) {
				doNotFollowTypes = getFlowTypesNotToFollow();
			}
			// Now we have an initial address set so lets flow "to" it.
			FollowFlow codeFlow = new FollowFlow(program, addressSet, doNotFollowTypes);
			selectionAddressSet = codeFlow.getFlowToAddressSet(monitor);
		}
		else {
			FlowType[] doNotFollowTypes = null; // Default is Follow All Flows.
			if (selectionType == SELECT_LIMITED_FLOWS_FROM) {
				doNotFollowTypes = getFlowTypesNotToFollow();
			}
			// Now we have an initial address set so lets flow from it.
			FollowFlow codeFlow = new FollowFlow(program, addressSet, doNotFollowTypes);
			selectionAddressSet = codeFlow.getFlowAddressSet(monitor);
		}

		if (monitor.isCancelled()) {
			return;
		}

		ProgramSelection selection = new ProgramSelection(selectionAddressSet);
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);

	}

	/**
	 * Determines the flow types that we do not want to follow according to the
	 * follow flow properties that are set to false.
	 * @return array of FlowTypes that should not be followed based on the
	 * current SelectByFlow property settings.
	 */
	public FlowType[] getFlowTypesNotToFollow() {
		ArrayList<FlowType> notFollowed = new ArrayList<FlowType>(6);
		if (!followComputedCall) {
			notFollowed.add(RefType.COMPUTED_CALL);
		}
		if (!followConditionalCall) {
			notFollowed.add(RefType.CONDITIONAL_CALL);
		}
		if (!followUnconditionalCall) {
			notFollowed.add(RefType.UNCONDITIONAL_CALL);
		}
		if (!followComputedJump) {
			notFollowed.add(RefType.COMPUTED_JUMP);
		}
		if (!followConditionalJump) {
			notFollowed.add(RefType.CONDITIONAL_JUMP);
		}
		if (!followUnconditionalJump) {
			notFollowed.add(RefType.UNCONDITIONAL_JUMP);
		}
		if (!followPointers) {
			notFollowed.add(RefType.INDIRECTION);
		}
		return notFollowed.toArray(new FlowType[notFollowed.size()]);
	}

	/**
	 * selectSubroutines selects all the subroutines that contain code units from
	 * the initial address set passed in as a parameter.
	 * @param monitor a cancellable task monitor
	 * @param startAddresses the initial addresses that should be used to select
	 * subroutines.
	 */
	private AddressSet selectSubroutines(TaskMonitor monitor, Program program,
			AddressSet startAddresses) throws CancelledException {
		// Create a new address set to hold the entire selection.
		AddressSet newAddressSet = new AddressSet();

		// If we don't have any addresses simply return.
		if ((startAddresses == null) || (startAddresses.getNumAddresses() <= 0)) {
			return newAddressSet;
		}

		monitor.initialize(startAddresses.getNumAddresses());

		CodeBlockModel cbm = blockModelService.getActiveSubroutineModel();
		CodeBlockIterator iter = cbm.getCodeBlocksContaining(startAddresses, monitor);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				return newAddressSet;
			}

			CodeBlock block = iter.next();
			newAddressSet.add(block);
			monitor.incrementProgress(block.getNumAddresses());
		}

		return newAddressSet;
	}

	/**
	 * Selects subroutines that are not directly referenced. 
	 * This is commonly referred to as DEAD code.
	 * @param monitor a cancellable task monitor
	 * @return address set containing the dead subroutines
	 * @throws CancelledException
	 */
	private AddressSet selectDeadSubroutines(TaskMonitor monitor, Program program,
			AddressSet startAddresses) throws CancelledException {

		// Create a new address set to hold the entire selection.
		AddressSet newAddressSet = new AddressSet();
		// If we don't have any addresses simply return.
		if ((startAddresses == null) || (startAddresses.getNumAddresses() <= 0)) {
			return newAddressSet;
		}

		monitor.initialize(startAddresses.getNumAddresses());

		ReferenceManager rm = program.getReferenceManager();
		CodeBlockModel cbm = blockModelService.getActiveSubroutineModel();
		CodeBlockIterator cbIter = cbm.getCodeBlocksContaining(startAddresses, monitor);

		while (cbIter.hasNext()) {
			if (monitor.isCancelled()) {
				return newAddressSet;
			}

			CodeBlock block = cbIter.next();
			monitor.setMessage(block.getName());
			if (!blockHasReferences(rm, block)) {
				newAddressSet.add(block);
			}
			monitor.incrementProgress(block.getNumAddresses());
		}

		return newAddressSet;
	}

	private boolean blockHasReferences(ReferenceManager referenceManager, CodeBlock block) {
		Address[] starts = block.getStartAddresses();
		for (int i = 0; i < starts.length; i++) {
			ReferenceIterator refIter = referenceManager.getReferencesTo(starts[i]);
			while (refIter.hasNext()) {
				Reference ref = refIter.next();
				if (ref.isMemoryReference()) {
					return true; // somebody is referencing this block start
				}
			}
		}
		return false;
	}

	/**
	 * selectFunctions selects all the functions that contain code units from
	 * the initial address set passed in as a parameter.
	 * @param monitor a cancellable task monitor
	 * @param startAddresses the initial addresses that should be used to select
	 * functions.
	 */
	private AddressSet selectFunctions(TaskMonitor monitor, Program program,
			AddressSet startAddresses) {
		// Create a new address set to hold the entire selection.
		AddressSet newAddressSet = new AddressSet();

		// If we don't have any addresses simply return.
		if ((startAddresses == null) || (startAddresses.getNumAddresses() <= 0)) {
			return newAddressSet;
		}

		monitor.initialize(startAddresses.getNumAddresses());

		// Loop to remove function codeunits 
		// starting address set and add the entire function to the new address set.
		FunctionManager functionManager = program.getFunctionManager();
		Iterator<Function> iter = functionManager.getFunctionsOverlapping(startAddresses);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				return newAddressSet;
			}

			Function f = iter.next();
			AddressSetView body = f.getBody();
			newAddressSet.add(body);
			monitor.incrementProgress(body.getNumAddresses());
		}

		return newAddressSet;
	}

	private void selectChangeSet(NavigatableActionContext context) {
		ProgramChangeSet cs = context.getProgram().getChanges();
		ProgramChangeSet pcs = cs;
		ProgramSelection selection = new ProgramSelection(pcs.getAddressSet());
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);
	}

	private void setupActions() {

		int subMenuGroupPosition = 1;

		selectProgramChangesAction =
			new NavigatableContextAction("Select Program Changes", getName()) {
				@Override
				public void actionPerformed(NavigatableActionContext context) {
					selectChangeSet(context);
				}

				@Override
				protected boolean isEnabledForContext(NavigatableActionContext context) {
					Program program = context.getProgram();
					ProgramChangeSet cs = program.getChanges();
					return cs != null && cs.hasChanges();
				}
			};
		selectProgramChangesAction.setMenuBarData(new MenuData(new String[] { "Select",
			"Program Changes" }, null, SelectByFlowAction.GROUP));

		selectProgramChangesAction.setHelpLocation(new HelpLocation(HelpTopics.SELECTION,
			selectProgramChangesAction.getName()));
		selectProgramChangesAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectProgramChangesAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(selectProgramChangesAction);

		/**
		 * Select by Following All Flows From setup
		 */
		selectAllFlowsFromAction =
			new SelectByFlowAction("Select All Flows From", this, SELECT_ALL_FLOWS_FROM);
		selectAllFlowsFromAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectAllFlowsFromAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectAllFlowsFromAction);

		/**
		 * Select by Following All Flows To setup
		 */
		selectAllFlowsToAction =
			new SelectByFlowAction("Select All Flows To", this, SELECT_ALL_FLOWS_TO);
		selectAllFlowsToAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectAllFlowsToAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectAllFlowsToAction);

		/**
		 * Select by Following Limited Flows From setup
		 */
		selectLimitedFlowsFromAction =
			new SelectByFlowAction("Select Limited Flows From", this, SELECT_LIMITED_FLOWS_FROM);
		selectLimitedFlowsFromAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectLimitedFlowsFromAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectLimitedFlowsFromAction);

		/**
		 * Select by Following Limited Flows To setup
		 */
		selectLimitedFlowsToAction =
			new SelectByFlowAction("Select Limited Flows To", this, SELECT_LIMITED_FLOWS_TO);
		selectLimitedFlowsToAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectLimitedFlowsToAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectLimitedFlowsToAction);

		/**
		 * Select Subroutine setup
		 */
		selectSubroutineAction =
			new SelectByFlowAction("Select Subroutine", this, SELECT_SUBROUTINES);
		selectSubroutineAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectSubroutineAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectSubroutineAction);

		/**
		 * Select Subroutine setup
		 */
		selectDeadSubroutineAction =
			new SelectByFlowAction("Select Dead Subroutine", this, SELECT_DEAD_SUBROUTINES);
		selectDeadSubroutineAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectDeadSubroutineAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectDeadSubroutineAction);

		/**
		 * Select Function setup
		 */
		selectFunctionAction = new SelectByFlowAction("Select Function", this, SELECT_FUNCTIONS);
		selectFunctionAction.getMenuBarData().setMenuSubGroup(
			Integer.toString(subMenuGroupPosition++));
		selectFunctionAction.addToWindowWhen(ListingActionContext.class);
		tool.addAction(selectFunctionAction);

	}

	/**
	 * Task for computing selection
	 */
	public class SelectByFlowTask extends Task {

		int selectionType;
		AddressSet addressSet;
		private final NavigatableActionContext context;

		SelectByFlowTask(NavigatableActionContext context, int selectionType)
				throws InvalidInputException {
			super(selectionTypes[selectionType], true, true, true);
			this.context = context;
			Program program = context.getProgram();
			this.selectionType = selectionType;
			addressSet = new AddressSet(context.getSelection());
			if (this.addressSet.isEmpty()) {
				if (selectionType == SELECT_DEAD_SUBROUTINES) {
					addressSet.add(program.getMemory());
				}
				else {
					Address location = context.getAddress();
					if (location != null) {
						addressSet.addRange(location, location);
					}
					else {
						throw new InvalidInputException("Can not determine current location");
					}
				}
			}
		}

		@Override
		public void run(TaskMonitor monitor) {
			performSelection(monitor, context, selectionType, addressSet);
		}

	}
}
