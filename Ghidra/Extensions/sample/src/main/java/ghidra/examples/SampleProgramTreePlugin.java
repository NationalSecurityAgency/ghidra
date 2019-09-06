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
package ghidra.examples;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.cmd.module.CreateDefaultTreeCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * Sample plugin to show how to create a new program tree and organize it
 * into folders and fragments.
 *
 *
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Sample Program Tree plugin",
	description = "This plugin demonstrates how to organize a program tree."
)
//@formatter:on
public class SampleProgramTreePlugin extends ProgramPlugin {
	private Listing listing;

	/**
	 * Construct a new SampleProgramTreePlugin.
	 * @param tool tool that will contain this plugin
	 */
	public SampleProgramTreePlugin(PluginTool tool) {
		super(tool, false, false); // we consume neither location nor selection events
		createActions();
	}

	/**
	 * create the action and call the subroutine that handles it
	 */
	private void createActions() {
		DockingAction action = new DockingAction("Create Sample Tree", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				modularize();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		action.setMenuBarData(
			new MenuData(new String[] { "Misc", "Create Sample Tree" }, null, null));
		action.setDescription("Plugin to create a program tree and modularize accordingly");
		tool.addAction(action);

	}// end of createActions()

	/**
	 * Method Modularize.
	 */
	private void modularize() {
		BackgroundCommand cmd = new ModularizeCommand();

		tool.executeBackgroundCommand(cmd, currentProgram);
	}

	/**
	 * Background command that will create the new tree and organize it.
	 *
	 */
	class ModularizeCommand extends BackgroundCommand {
		private int fragment_count = 0;
		private String programTreeName = "Sample Tree";

		ModularizeCommand() {
			super("Sample Tree Creation", true, true, false);
		}

		@Override
		public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
			Program program = (Program) obj;

			listing = program.getListing();

			createDefaultTreeView(program, programTreeName);

			Memory mem = program.getMemory();

			ProgramModule root_module = listing.getRootModule(programTreeName);

			AddressSet set = new AddressSet(mem);

			try {
				root_module.createModule("Fragments");
			}
			catch (DuplicateNameException e) {
				// don't care???
			}
			ProgramModule frags = listing.getModule(programTreeName, "Fragments");

			long startCount = set.getNumAddresses();
			monitor.initialize(startCount);
			while (!monitor.isCancelled() && !set.isEmpty()) {
				MemoryBlock block = mem.getBlock(set.getMinAddress());
				Address start = block.getStart();
				Address end = block.getEnd();

				set.deleteRange(block.getStart(), block.getEnd());

				long numLeft = set.getNumAddresses();
				monitor.setProgress(startCount - numLeft);

				String mod_name = block.getName();

				monitor.setMessage("Module " + start + " : " + mod_name);

				ProgramModule mod = make_module(mod_name, frags);
				makeFragment(start, end, "frag_" + fragment_count, mod);
				fragment_count++;
			}

			return true;
		}

		private void createDefaultTreeView(Program program, String defaultTreeName) {
			String treeName = defaultTreeName;
			int oneUp = 1;
			while (listing.getRootModule(treeName) != null) {
				treeName = defaultTreeName + "_" + oneUp;
				oneUp++;
			}
			CreateDefaultTreeCmd cmd = new CreateDefaultTreeCmd(defaultTreeName);
			if (tool.execute(cmd, program)) {
				tool.setStatusInfo(cmd.getStatusMsg());
			}
		}

		/**
		 * Method make_module.
		 * @param start
		 * @param entry_address
		 * @param prev_name
		 * @param code
		 */
		private ProgramModule make_module(String moduleName, ProgramModule parent) {
			String modName = moduleName;

			int oneUp = 1;
			ProgramModule newMod = listing.getModule(programTreeName, moduleName);
			while (newMod == null) {
				try {
					newMod = parent.createModule(modName);
				}
				catch (DuplicateNameException e) {
				}
				modName = moduleName + "_" + oneUp;
				oneUp++;
			}
			return newMod;
		}

		/**
		 * Method make_frag.
		 * @param start
		 * @param entry_address
		 * @param prev_name
		 */
		private ProgramFragment makeFragment(Address start, Address end, String fragmentName,
				ProgramModule parent) {

			try {
				parent.createFragment(fragmentName);
			}
			catch (DuplicateNameException e) {
			}
			ProgramFragment frag = listing.getFragment(programTreeName, fragmentName);

			try {
				frag.move(start, end);
			}
			catch (NotFoundException e) {
				Msg.error(this,
					"couln't find addresses for fragment " + fragmentName + " : " + start, e);
			}
			return frag;
		}
	}
}
