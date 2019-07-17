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

import java.util.*;

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
 * Command that applies the "module" algorithm to a specified Module or
 * Fragment. 
 * Gets an iterator over the code blocks containing the selected folder or fragment.
 * Creates a folder for each code block in the iterator.
 * For each code block, gets an iterator over code blocks containing the code block.
 * For each of these code blocks, create a fragment and move the code units to the fragment.  
 * 
 *   
 *
 */
public class ModuleAlgorithmCmd extends BackgroundCommand {

	private static final String NEW_MODULE_SUFFIX = " [Subroutine Tree]";
	private static final String PROGRAM_CHANGED_MESSAGE =
		"Modularization did not run: Program Tree has changed since the algorithm was scheduled.";

	private GroupPath groupPath;
	private String treeName;
	private BlockModelService blockModelService;
	private String partitioningModelName;
	private Set<ProgramModule> moduleSet = new HashSet<ProgramModule>();
	private PluginTool tool;

	/**
	 * Constructor
	 * @param path path the source module or fragment where the algorithm
	 * will be applied
	 * @param treeName name of the tree
	 * @param blockModelService service that has the known block models
	 * @param partitioningModelName name of the model to use
	 */
	public ModuleAlgorithmCmd(GroupPath path, String treeName, BlockModelService blockModelService,
			String partitioningModelName) {
		super("Modularize By Subroutine", false, true, true);
		groupPath = path;
		this.treeName = treeName;
		this.blockModelService = blockModelService;
		this.partitioningModelName = partitioningModelName;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {

		Program program = (Program) obj;
		ProgramModule root = program.getListing().getRootModule(treeName);

		try {
			boolean status = applyModel(program, root, monitor);
			if (status && getStatusMsg() != null && tool != null) {
				tool.setStatusInfo(getStatusMsg());
			}
			return status;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			setStatusMsg("Modularize failed: " + msg);
		}
		return false;
	}

	public void setPluginTool(PluginTool tool) {
		this.tool = tool;
	}

	/**
	 * 
	 * @param monitor
	 * @throws NotFoundException
	 * @throws NotEmptyException
	 * @throws DuplicateNameException
	 */
	private boolean applyModel(Program program, ProgramModule root, TaskMonitor monitor)
			throws NotFoundException, NotEmptyException, DuplicateNameException {

		Group group = groupPath.getGroup(program, treeName);
		if (group == null) {
			setStatusMsg(PROGRAM_CHANGED_MESSAGE);
			return true; // ignore this because the program has changed since this command was
		}                // scheduled

		SubroutineBlockModel partitioningModel = null;
		if (partitioningModelName == null) {
			partitioningModel =
				(SubroutineBlockModel) blockModelService.getActiveSubroutineModel(program);
		}
		else {
			partitioningModel =
				(SubroutineBlockModel) blockModelService.getNewModelByName(partitioningModelName,
					program);
		}
		SubroutineBlockModel baseModel = partitioningModel.getBaseSubroutineModel();

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
					cbi = baseModel.getCodeBlocks(monitor);
					module = program.getListing().getRootModule(treeName);
				}
				else {
					module = (ProgramModule) group;
					String name = module.getName();
					if (name.indexOf(NEW_MODULE_SUFFIX) < 0) {
						module.setName(module.getName() + NEW_MODULE_SUFFIX);
					}
					cbi = baseModel.getCodeBlocksContaining(module.getAddressSet(), monitor);
				}
			}
			else {  // group is fragment
				if (parent == null) {
					parent = program.getListing().getRootModule(treeName);
				}
				ProgramFragment fragment = (ProgramFragment) group;
				cbi = baseModel.getCodeBlocksContaining(fragment, monitor);
				module = createModule(parent, fragment.getName() + NEW_MODULE_SUFFIX);
				String newName = module.getName();
				parent.moveChild(newName, index);
			}
			while (cbi.hasNext()) {
				monitor.checkCanceled();
				CodeBlock cb = cbi.next();
				monitor.setMessage("Processing code block @ " + cb.getMinAddress().toString(true));
				ArrayList<CodeBlock> list = new ArrayList<CodeBlock>();
				CodeBlockIterator cbi2 = partitioningModel.getCodeBlocksContaining(cb, monitor);
				while (cbi2.hasNext() && !monitor.isCancelled()) {
					CodeBlock cb2 = cbi2.next();
					list.add(cb2);
				}
				ProgramModule parentModule;
				if (list.size() > 1) {
					parentModule = createModule(module, cb);
				}
				else {
					parentModule = module;
				}
				for (CodeBlock codeBlock : list) {
					monitor.checkCanceled();
					ProgramFragment fragment = createFragment(parentModule, codeBlock);
					moveCodeUnits(fragment, codeBlock, monitor);
				}
			}
		}
		catch (CancelledException e) {
			setStatusMsg("Modularize was cancelled");
			return false;
		}
		cleanTree(root);
		return true;
	}

	/**
	 * Create a fragment with the name as the name of the given block; 
	 * append a one-up number if we get a DuplicateNameException.
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
	 * Create a fragment with the name as the name of the given block; 
	 * append a one-up number if we get a DuplicateNameException.
	 * @param root parent module
	 * @param block code block
	 * @return Fragment new fragment
	 */
	private ProgramModule createModule(ProgramModule root, CodeBlock block) {

		boolean done = false;
		int index = 0;
		String baseName = block.getName();
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
	 * Method moveCodeUnits.
	 * @param fragment
	 * @param block
	 * @param monitor
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

	/**
	 * Method cleanTree.
	 * Removes all empty fragments and empty modules
	 * 
	 * @param module the root branch to be cleaned.  Can be branch or entire tree.
	 * @throws NotEmptyException if attempting to remove a module or fragment that is not empty
	 */
	private void cleanTree(ProgramModule module) throws NotEmptyException {
		if (module == null || moduleSet.contains(module)) {
			return;
		}
		moduleSet.add(module);

		if (module.getNumChildren() == 0) {
			return;
		}
		/// for each child, if fragment and empty delete the child
		/// otherwise, clean the child
		/// if module has no children, delete it
		Group[] children = module.getChildren();
		for (Group child : children) {
			if (child instanceof ProgramModule) {
				ProgramModule childModule = (ProgramModule) child;
				cleanTree(childModule);
				if (childModule.getNumChildren() == 0) {
					module.removeChild(childModule.getName());
				}
			}
			else {
				ProgramFragment fragment = (ProgramFragment) child;
				if (fragment.isEmpty()) {
					module.removeChild(fragment.getName());
				}
			}
		}
		if (module.getParents().length != 0) {
			try {
				String numKidsPrefix = "   [";
				String currentName = module.getName();
				int prefix = currentName.indexOf(numKidsPrefix);
				String baseName = (prefix < 0) ? currentName : currentName.substring(0, prefix);
				module.setName(baseName + numKidsPrefix + module.getNumChildren() + "]");
			}
			catch (DuplicateNameException e) {
			}
		}
	}

	/**
	 * Create a Module with the name as the name specified; 
	 * append a one-up number if we get a DuplicateNameException.
	 * @param module parent module
	 * @param newName new name
	 * @return Module new Module
	 */
	private ProgramModule createModule(ProgramModule module, String newName) {

		boolean done = false;
		int index = 0;
		String baseName = new String(newName);
		String name = baseName;
		while (!done) {
			try {
				return module.createModule(name);
			}
			catch (DuplicateNameException e) {
				++index;
				name = baseName + "(" + index + ")";
			}
		}
		return null;
	}
}
