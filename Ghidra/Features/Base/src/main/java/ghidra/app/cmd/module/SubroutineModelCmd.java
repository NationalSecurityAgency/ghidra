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
package ghidra.app.cmd.module;

import ghidra.app.services.BlockModelService;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * Command that organizes a Module or Fragment according to a specified block
 * model. This organization produces a "flat" (single layer) partitioning.
 * 
 * @see ghidra.program.model.block.CodeBlockModel
 * 
 * 
 *
 */
public class SubroutineModelCmd extends BackgroundCommand {

	private static final String NEW_MODULE_SUFFIX = " [Subroutines]";
	private static final String PROGRAM_CHANGED_MESSAGE =
		"Organize algorithm did not run: Program Tree has changed since the algorithm was scheduled.";

	private BlockModelService blockModelService;
	private String treeName;
	private GroupPath groupPath;
	private String modelName;
	private PluginTool tool;

	/**
	 * Constructor
	 * 
	 * @param groupPath group path of the affected Module or Fragment
	 * @param treeName name of the tree where group exists
	 * @param blockModelService service that has the known block models
	 * @param modelName name of the model to use
	 */
	public SubroutineModelCmd(GroupPath groupPath, String treeName,
			BlockModelService blockModelService, String modelName) {
		super("Organize By Subroutine", false, true, true);
		this.groupPath = groupPath;
		this.treeName = treeName;
		this.blockModelService = blockModelService;
		this.modelName = modelName;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject,
	 *      ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;
		ProgramModule root = program.getListing().getRootModule(treeName);

		try {
			boolean status = changeModel(program, root, monitor);
			if (status && getStatusMsg() != null && tool != null) {
				tool.setStatusInfo(getStatusMsg());
			}
			return status;
		}
		catch (NotFoundException e) {
			setStatusMsg("Error moving code units: " + e);
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			setStatusMsg("Error invoking model " + modelName + ": " + msg);
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return false;
	}

	public void setPluginTool(PluginTool tool) {
		this.tool = tool;
	}

	private boolean changeModel(Program program, ProgramModule root, TaskMonitor monitor)
			throws NotEmptyException, NotFoundException, DuplicateNameException {

		Group group = groupPath.getGroup(program, treeName);
		if (group == null) {
			setStatusMsg(PROGRAM_CHANGED_MESSAGE);
			return true; // ignore this because the program has changed since this command was
		}                // scheduled

		SubroutineBlockModel subModel = null;
		if (modelName == null) {
			subModel = (SubroutineBlockModel) blockModelService.getActiveSubroutineModel(program);
		}
		else {
			subModel =
				(SubroutineBlockModel) blockModelService.getNewModelByName(modelName, program);
		}

		ProgramModule parent = null;
		GroupPath parentPath = groupPath.getParentPath();
		if (parentPath != null) {
			parent = (ProgramModule) parentPath.getGroup(program, treeName);
			if (parent == null && parentPath.getPathCount() > 1) {
				setStatusMsg(PROGRAM_CHANGED_MESSAGE);
				return true;// ignore this because the program has changed since this command was
			}                // scheduled
		}
		int index = 0;
		if (parent != null) {
			index = parent.getIndex(group.getName());
		}

		try {
			CodeBlockIterator cbi = null;
			ProgramModule module = null;
			if (group instanceof ProgramModule) {
				if (group.equals(root)) {
					cbi = subModel.getCodeBlocks(monitor);
					module = program.getListing().getRootModule(treeName);
				}
				else {
					module = (ProgramModule) group;
					String name = module.getName();
					if (name.indexOf(NEW_MODULE_SUFFIX) == -1) {
						module.setName(module.getName() + NEW_MODULE_SUFFIX);
					}
					cbi = subModel.getCodeBlocksContaining(module.getAddressSet(), monitor);
				}
			}
			else {  // group is fragment
				if (parent == null) {
					parent = program.getListing().getRootModule(treeName);
				}
				ProgramFragment fragment = (ProgramFragment) group;
				cbi = subModel.getCodeBlocksContaining(fragment, monitor);
				module = createModule(parent, fragment.getName() + NEW_MODULE_SUFFIX);
				String newName = module.getName();
				parent.moveChild(newName, index);
			}
			while (cbi.hasNext()) {
				CodeBlock cb = cbi.next();
				ProgramFragment subFragment = createFragment(module, cb);
				moveCodeUnits(subFragment, cb, monitor);
			}
		}
		catch (CancelledException e) {
			setStatusMsg("Organize was cancelled");
			return false;
		}
		AbstractModularizationCmd.cleanTree(root);
		return true;
	}

	/**
	 * Create a fragment with the name as the name of the given block; append a
	 * one-up number if we get a DuplicateNameException.
	 * 
	 * @param root parent module
	 * @param block code block
	 * @return Fragment new fragment
	 */
	private ProgramFragment createFragment(ProgramModule root, CodeBlock block) {
		boolean done = false;
		int index = 0;
		String baseName = block.getName();
		String name = baseName;
		while (!done) {

			try {
				return root.createFragment(name);
			}
			catch (DuplicateNameException e) {
				++index;
				name = baseName + "(" + index + ")";
			}
		}
		return null;
	}

	/**
	 * Create a fragment with the name as the name of the given block; append a
	 * one-up number if we get a DuplicateNameException.
	 * 
	 * @param root parent module
	 * @param block code block
	 * @return Fragment new fragment
	 */
	private ProgramModule createModule(ProgramModule root, String nodeName) {

		boolean done = false;
		int index = 0;
		//String baseName = block.getName();
		//String name = baseName;
		String baseName = new String(nodeName);
		String name = baseName;
		while (!done) {
			try {
				return root.createModule(name);
			}
			catch (DuplicateNameException e) {
				++index;
				name = baseName + "(" + index + ")";
			}
		}
		return null;
	}

	/**
	 * Method moveCodeUnits. Moves the code units into a Fragment
	 * 
	 * @param fragment the Fragment where the code units are moved to.
	 * @param block the CodeBlock containing the code to be moved.
	 * @param monitor the TaskMonitor to allow for cancelling.
	 * @throws NotFoundException
	 */
	private void moveCodeUnits(ProgramFragment fragment, CodeBlock block, TaskMonitor monitor)
			throws NotFoundException {

		AddressRangeIterator iter = block.getAddressRanges();
		while (iter.hasNext() && !monitor.isCancelled()) {
			AddressRange range = iter.next();
			fragment.move(range.getMinAddress(), range.getMaxAddress());
		}
	}

}
