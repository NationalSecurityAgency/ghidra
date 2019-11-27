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
import java.util.function.Consumer;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.*;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractModularizationCmd extends BackgroundCommand {
	protected Program program;
	private GroupPath groupPath;
	private String treeName;
	private CodeBlockModel codeBlockModel;
	private ProgramSelection selection;
	private String name;
	private boolean processEntireProgram;
	private Group selectedGroup;
	protected ProgramModule destinationModule;
	private AddressSetView validAddresses;

	protected TaskMonitor monitor;

	public AbstractModularizationCmd(String name, GroupPath path, String treeName,
			ProgramSelection selection, CodeBlockModel blockModel) {
		super(name, true, true, false);
		this.name = name;
		this.groupPath = path;
		this.treeName = treeName;
		this.selection = selection;
		this.codeBlockModel = blockModel;
	}

	protected abstract void applyModel() throws CancelledException;

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {

		program = (Program) obj;
		monitor = taskMonitor;
		monitor.setIndeterminate(true);
		ProgramModule rootModule = program.getListing().getRootModule(treeName);
		selectedGroup = groupPath.getGroup(program, treeName);
		processEntireProgram = selectedGroup.equals(rootModule);
		destinationModule =
			selectedGroup instanceof ProgramModule ? (ProgramModule) selectedGroup : rootModule;
		processEntireProgram = selectedGroup.equals(rootModule);
		validAddresses = getAddressesForGroup();

		try {
			applyModel();
			cleanEmpty();
			return true;
		}
		catch (CancelledException e) {
			setStatusMsg("Cancelled");
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception modularizing the program tree", e);
			setStatusMsg("Unexpected Exception (see console)");
		}
		return false;
	}

	protected void cleanEmpty() throws NotEmptyException {
		ProgramModule rootModule = program.getListing().getRootModule(treeName);
		cleanTreeWithoutRename(rootModule);
	}

	private AddressSetView getAddressesForGroup() {

		if (processEntireProgram) {
			return program.getMemory();
		}

		if (selectedGroup instanceof ProgramModule) {
			ProgramModule module = (ProgramModule) selectedGroup;
			return getModuleAddresses(module);
		}

		return (ProgramFragment) selectedGroup;
	}

	private AddressSet getModuleAddresses(ProgramModule mod) {
		AddressSet set = new AddressSet();

		// recursively go through module to build up address set
		getAddressSet(mod, set);

		return set;
	}

	//code to get the address set if the root or a frag is not selected
	private void getAddressSet(Group group, AddressSet set) {

		if (group instanceof ProgramFragment) {
			AddressRangeIterator iter = ((ProgramFragment) group).getAddressRanges();
			while (iter.hasNext() && !monitor.isCancelled()) {
				AddressRange range = iter.next();
				set.add(range);
			}
		}
		else {
			Group[] groups = ((ProgramModule) group).getChildren();
			for (Group g : groups) {
				getAddressSet(g, set);
			}
		}
	}

	protected GDirectedGraph<CodeBlockVertex, CodeBlockEdge> createCallGraph()
			throws CancelledException {

		Map<CodeBlock, CodeBlockVertex> instanceMap = new HashMap<>();
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = GraphFactory.createDirectedGraph();

		CodeBlockIterator codeBlocks = getCallGraphBlocks();
		while (codeBlocks.hasNext()) {
			CodeBlock block = codeBlocks.next();

			if (selection != null && !selection.contains(block.getFirstStartAddress())) {
				continue;
			}

			CodeBlockVertex fromVertex = instanceMap.get(block);
			if (fromVertex == null) {
				fromVertex = new CodeBlockVertex(block);
				instanceMap.put(block, fromVertex);
				graph.addVertex(fromVertex);
			}

			//destinations section
			addEdgesForDestinations(graph, fromVertex, block, instanceMap);
		}
		return graph;
	}

	private void addEdgesForDestinations(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph,
			CodeBlockVertex fromVertex, CodeBlock sourceBlock,
			Map<CodeBlock, CodeBlockVertex> instanceMap) throws CancelledException {

		CodeBlockReferenceIterator iterator = sourceBlock.getDestinations(monitor);
		while (iterator.hasNext()) {
			monitor.checkCanceled();

			CodeBlockReference destination = iterator.next();
			CodeBlock targetBlock = getDestinationBlock(destination);
			if (targetBlock == null) {
				continue; // no block found
			}

			CodeBlockVertex targetVertex = instanceMap.get(targetBlock);
			if (targetVertex == null) {
				targetVertex = new CodeBlockVertex(targetBlock);
				instanceMap.put(targetBlock, targetVertex);
			}

			graph.addVertex(targetVertex);
			graph.addEdge(new CodeBlockEdge(fromVertex, targetVertex));
		}
	}

	private CodeBlock getDestinationBlock(CodeBlockReference destination)
			throws CancelledException {

		Address targetAddress = destination.getDestinationAddress();
		CodeBlock targetBlock = codeBlockModel.getFirstCodeBlockContaining(targetAddress, monitor);
		if (targetBlock == null) {
			return null; // no code found for call; external?
		}

		Address blockAddress = targetBlock.getFirstStartAddress();
		if (skipAddress(blockAddress)) {
			return null;
		}

		return targetBlock;
	}

	private boolean skipAddress(Address address) {

		if (processEntireProgram) {
			return false;
		}

		return !validAddresses.contains(address);
	}

	private CodeBlockIterator getCallGraphBlocks() throws CancelledException {

		if (processEntireProgram) {
			return codeBlockModel.getCodeBlocks(monitor);
		}

		if (selectedGroup instanceof ProgramModule) {
			ProgramModule module = (ProgramModule) selectedGroup;
			setModuleName(module, module.getName() + " [" + name + "]");
		}

		return codeBlockModel.getCodeBlocksContaining(validAddresses, monitor);
	}

	protected void makeFragment(Program p, ProgramModule module, CodeBlockVertex vertex) {
		if (vertex.isDummy()) {
			return;
		}

		CodeBlock block = vertex.getCodeBlock();

		ProgramFragment fragment = createFragment(module, block);

		AddressRangeIterator iter = block.getAddressRanges();
		while (iter.hasNext() && !monitor.isCancelled()) {
			AddressRange range = iter.next();
			try {
				fragment.move(range.getMinAddress(), range.getMaxAddress());
			}
			catch (NotFoundException e) {
				// this shouldn't happen
				Msg.error(this, "Error moving addresses to fragment: " + fragment.getName(), e);
			}

		}
	}

	protected ProgramFragment createFragment(ProgramModule root, CodeBlock block) {
		boolean done = false;
		String blockName = block.getName();
		while (!done) {
			try {
				return root.createFragment(blockName);
			}
			catch (DuplicateNameException e) {
				blockName += "*";
			}
		}
		return null;
	}

	protected ProgramModule createModule(ProgramModule parent, String moduleName) {
		int index = 0;
		while (true) {
			try {
				return parent.createModule(moduleName);
			}
			catch (DuplicateNameException e) {
				++index;
				moduleName = moduleName + "(" + index + ")";
			}
		}
	}

	private void setModuleName(ProgramModule module, String name) {
		String attemptedName = name;
		int count = 0;
		while (true) {
			try {
				module.setName(attemptedName);
				return;
			}
			catch (DuplicateNameException e) {
				attemptedName = name + "_" + ++count;
			}
		}
	}

	private void cleanTreeWithoutRename(ProgramModule module) throws NotEmptyException {
		Consumer<ProgramModule> doNotRename = m -> {
			// do nothing
		};
		Set<ProgramModule> moduleSet = new HashSet<ProgramModule>();
		cleanTree(module, doNotRename, moduleSet);
	}

	/**
	 * Method cleanTree. Removes all empty fragments and empty modules
	 * 
	 * @param module the root branch to be cleaned. Can be branch or entire tree
	 * @throws NotEmptyException if attempting to remove a module or fragment that is not empty
	 */
	static void cleanTree(ProgramModule module) throws NotEmptyException {

		Consumer<ProgramModule> renamer = m -> rename(module);
		Set<ProgramModule> moduleSet = new HashSet<ProgramModule>();
		cleanTree(module, renamer, moduleSet);
	}

	private static void cleanTree(ProgramModule module, Consumer<ProgramModule> renamer,
			Set<ProgramModule> visited) throws NotEmptyException {
		if (module == null || visited.contains(module)) {
			return;
		}

		visited.add(module);
		if (module.getNumChildren() == 0) {
			return;
		}

		// for each child, if fragment and empty delete the child otherwise, clean the child
		// if module has no children, delete it
		Group[] children = module.getChildren();
		for (Group child : children) {
			if (child instanceof ProgramModule) {
				ProgramModule childModule = (ProgramModule) child;
				cleanTree(childModule, renamer, visited);
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

		renamer.accept(module);
	}

	private static void rename(ProgramModule module) {
		try {
			String numKidsPrefix = "   [";
			String currentName = module.getName();
			int prefix = currentName.indexOf(numKidsPrefix);
			String baseName = (prefix < 0) ? currentName : currentName.substring(0, prefix);
			module.setName(baseName + numKidsPrefix + module.getNumChildren() + "]");
		}
		catch (DuplicateNameException e) {
			// not sure why we are squashing this?...better description needed
		}
	}

}
