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
package ghidra.app.plugin.core.select.qualified;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.NavigationUtils;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Plugin to extend selection features to include select data,
 * select instructions and select undefined.  Selection will occur
 * in the background with a status bar dialog that allows the user
 * to cancel select process. If a selection exists then the new
 * selection will be limited to a subset of the original selection.
 * If there isn't a selection before the select action is invoked, then the
 * select will be performed on the entire program.
 * 
 * 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Select Data, Instructions, and Undefined",
	description = "This plugin makes a selection of defined data,"
			+ " instructions, and undefined code units. The process of "
			+ "making the selection is done in the background and "
			+ "can be cancelled at any time. If a selection already exists, "
			+ "the new selection will be limited to a subset of the original selection."
			+ " If there isn't a selection when the action is invoked, "
			+ "then the select will be performed on the entire program.",
	eventsProduced = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class QualifiedSelectionPlugin extends Plugin {

	private DockingAction selectDataAction;
	private DockingAction selectInstructionsAction;
	private DockingAction selectUndefinedAction;

	private int SELECT_INSTRUCTIONS = 0;
	private int SELECT_UNDEFINED = 1;
	private int SELECT_DATA = 2;

	/**
	 * Constructs an instance of this plugin.
	 * 
	 * @param tool The tool required by this plugin to interact with its 
	 *        environment.
	 */
	public QualifiedSelectionPlugin(PluginTool tool) {
		super(tool);
		setupActions(tool);
	}

	private void setupActions(PluginTool tool) {
		selectDataAction = new QualifiedSelectionAction("Data") {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				selectData(context);
			}
		};
		tool.addAction(selectDataAction);

		selectInstructionsAction = new QualifiedSelectionAction("Instructions") {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				selectInstructions(context);
			}
		};
		tool.addAction(selectInstructionsAction);

		selectUndefinedAction = new QualifiedSelectionAction("Undefined") {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				selectUndefined(context);
			}
		};
		tool.addAction(selectUndefinedAction);

	}

	private void selectInstructions(NavigatableActionContext context) {
		Task task = new SelectTask("Select Instructions", context, SELECT_INSTRUCTIONS);
		tool.execute(task);
	}

	private void selectUndefined(NavigatableActionContext context) {
		Task task = new SelectTask("Select Undefined", context, SELECT_UNDEFINED);
		tool.execute(task);
	}

	private void selectData(NavigatableActionContext context) {
		Task task = new SelectTask("Select Data", context, SELECT_DATA);
		tool.execute(task);
	}

	/**
	 * Selects undefined data for the selection or program.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 */
	private void selectUndefined(TaskMonitor taskMonitor, NavigatableActionContext context) {
		AddressSet undefAddressSet = getUndefined(taskMonitor, context);
		ProgramSelection selection = new ProgramSelection(undefAddressSet);
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);
	}

	/**
	 * Selects instructions for the selection or program.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 */
	private void selectInstructions(TaskMonitor taskMonitor, NavigatableActionContext context) {
		AddressSet instrAddressSet = getInstructions(context, getStartSet(context), taskMonitor);
		ProgramSelection selection = new ProgramSelection(instrAddressSet);
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);
	}

	/**
	 * Selects defined data for the selection or program.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 */
	private void selectData(TaskMonitor taskMonitor, NavigatableActionContext context) {
		AddressSet dataAddressSet = getDefinedData(context, getStartSet(context), taskMonitor);
		ProgramSelection selection = new ProgramSelection(dataAddressSet);
		NavigationUtils.setSelection(tool, context.getNavigatable(), selection);
	}

	/**
	 * If there is a selection, this returns the selection address set.
	 * Otherwise it returns the program's address set.
	 * @return
	 */
	private AddressSetView getStartSet(ProgramLocationActionContext context) {
		Program program = context.getProgram();
		if (program == null) {
			return new AddressSet();
		}
		if (context.hasSelection()) {
			return context.getSelection();
		}
		return new AddressSet(program.getMemory());
	}

	/**
	 * <code>getUndefined</code> returns the undefined data associated with the selection
	 * or with the program if there isn't a selection.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 * @return AddressSet the undefined data address set.
	 */
	private AddressSet getUndefined(TaskMonitor taskMonitor, ProgramLocationActionContext context) {

		AddressSetView startSet = getStartSet(context);
		startSet = adjustToCodeUnitBoundaries(startSet, context);
		AddressSetView definedDataSet = getDefinedData(context, startSet, taskMonitor);
		if (taskMonitor.isCancelled()) {
			return new AddressSet();//return an empty address set...
		}
		AddressSetView instructionSet = getInstructions(context, startSet, taskMonitor);
		if (taskMonitor.isCancelled()) {
			return new AddressSet();//return an empty address set...
		}
		AddressSet notUndefinedSet = definedDataSet.union(instructionSet);
		AddressSet undefinedSet = startSet.subtract(notUndefinedSet);
		return undefinedSet;
	}

	private AddressSetView adjustToCodeUnitBoundaries(AddressSetView startSet,
			ProgramLocationActionContext context) {
		Program program = context.getProgram();
		AddressSet newSet = new AddressSet();
		AddressRangeIterator it = startSet.getAddressRanges();
		Listing listing = program.getListing();
		while (it.hasNext()) {
			AddressRange range = it.next();
			newSet.add(range);
			Address start = range.getMinAddress();
			CodeUnit cu = listing.getCodeUnitContaining(start);
			if (cu != null && !cu.getMinAddress().equals(start)) {
				newSet.addRange(cu.getMinAddress(), cu.getMaxAddress());
			}
		}
		return newSet;
	}

	/**
	 * <code>getDefinedData</code> returns the defined data associated with the selection
	 * or with the program if there isn't a selection.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 * @return AddressSet the defined data address set.
	 */
	private AddressSet getDefinedData(ProgramLocationActionContext context,
			AddressSetView startSet, TaskMonitor taskMonitor) {

		Program program = context.getProgram();
		Listing listing = program.getListing();
		AddressSet addressSet = new AddressSet();
		long numDefined = listing.getNumDefinedData(); // Get the total number since we can't easily get the number in the selection.
		taskMonitor.initialize((int) numDefined);
		int counter = 0;
		DataIterator diter = listing.getDefinedData(startSet, true);
		while (diter.hasNext() && !taskMonitor.isCancelled()) {
			counter++;
			taskMonitor.setProgress(counter);
			Data data = diter.next();
			addressSet.addRange(data.getMinAddress(), data.getMaxAddress());
		}
		return addressSet;
	}

	/**
	 * <code>getInstructions</code> returns the instructions associated with the selection
	 * or with the program if there isn't a selection.
	 * 
	 * @param taskMonitor The task monitor that will monitor task progress.
	 * @return AddressSet the instructions address set.
	 */
	private AddressSet getInstructions(ProgramLocationActionContext context,
			AddressSetView startSet, TaskMonitor taskMonitor) {
		Program program = context.getProgram();
		Listing listing = program.getListing();
		AddressSet addressSet = new AddressSet();
		long numInstruct = listing.getNumInstructions(); // Get the total number since we can't easily get the number in the selection.
		taskMonitor.initialize((int) numInstruct);
		int counter = 0;
		InstructionIterator initer = listing.getInstructions(startSet, true);
		while (initer.hasNext() && !taskMonitor.isCancelled()) {
			counter++;
			taskMonitor.setProgress(counter);
			Instruction instruct = initer.next();
			addressSet.addRange(instruct.getMinAddress(), instruct.getMaxAddress());
		}
		return addressSet;
	}

	/**
	 * Handles the progress bar that allow select process to run in 
	 * the background
	 * 
	 * 
	 */
	private class SelectTask extends Task {
		private int selectOption;
		private final NavigatableActionContext context;

		SelectTask(String name, NavigatableActionContext context, int selectOption) {
			super(name, true, true, true);
			this.context = context;
			this.selectOption = selectOption;
		}

		@Override
		public void run(TaskMonitor taskMonitor) {
			if (selectOption == SELECT_INSTRUCTIONS) {
				selectInstructions(taskMonitor, context);
			}
			else if (selectOption == SELECT_UNDEFINED) {
				selectUndefined(taskMonitor, context);
			}
			else if (selectOption == SELECT_DATA) {
				selectData(taskMonitor, context);
			}
		}
	}

	private abstract class QualifiedSelectionAction extends NavigatableContextAction {
		QualifiedSelectionAction(String name) {
			super(name, QualifiedSelectionPlugin.this.getName());
			setHelpLocation(new HelpLocation(HelpTopics.SELECTION, name));
			setEnabled(false);
			setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_SELECTION, name }, null,
				"Select Group 2"));
			addToWindowWhen(NavigatableActionContext.class);
		}
	}

}
