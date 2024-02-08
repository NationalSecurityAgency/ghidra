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
package ghidra.app.plugin.core.memory;

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramEvent;
import ghidra.program.util.ProgramLocation;

/**
 * <CODE>MemoryMapPlugin</CODE> displays a memory map of all blocks in
 * the current program's memory.  Options for Adding, Editing, and Deleting
 * those memory blocks are available.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Memory Map View",
	description = "This plugin provides the memory map component which allows users to add, remove, and edit memory blocks.",
	servicesRequired = { GoToService.class },
	eventsProduced = { ProgramLocationPluginEvent.class }
)
//@formatter:on
public class MemoryMapPlugin extends ProgramPlugin implements DomainObjectListener {

	private MemoryMapProvider provider;
	private GoToService goToService;
	private MemoryMapManager memManager;

	public MemoryMapPlugin(PluginTool tool) {
		super(tool);

		memManager = new MemoryMapManager(this);
		provider = new MemoryMapProvider(this);
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove
	 * itself from anything that it is registered to and release any resources.
	 */
	@Override
	public void dispose() {
		if (provider != null) {
			provider.dispose();
			provider = null;
		}
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}
		super.dispose();
	}

	/**
	 * This is the callback method for DomainObjectChangedEvents.
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {

		if (provider == null || !provider.isVisible()) {
			return;
		}
		if (ev.contains(MEMORY_BLOCK_ADDED, MEMORY_BLOCK_REMOVED, MEMORY_BLOCK_MOVED,
			MEMORY_BLOCK_SPLIT, MEMORY_BLOCKS_JOINED, RESTORED)) {
			this.provider.updateMap();
		}
		else if (ev.contains(ProgramEvent.MEMORY_BLOCK_CHANGED)) {
			this.provider.updateData();
		}
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		if (currentProgram != null) {
			programActivated(currentProgram);
		}
	}

	/**
	 * Subclass should override this method if it is interested in
	 * open program events.
	 */
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
		memManager.setProgram(program);
		provider.setProgram(program);
	}

	/**
	 * Subclass should override this method if it is interested in
	 * close program events.
	 */
	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
		memManager.setProgram(null);
		provider.setProgram(null);
	}

	MemoryMapManager getMemoryMapManager() {
		return memManager;
	}

	MemoryMapProvider getMemoryMapProvider() {
		return provider;
	}

	Memory getMemory() {
		return currentProgram.getMemory();
	}

	/**
	 *  Called when a memory location in a memory block line is selected in
	 *  the MemoryMapDialog.
	 */
	void blockSelected(MemoryBlock block, Address addr) {
		ProgramLocation loc = new ProgramLocation(currentProgram, addr);
		goToService.goTo(loc);
	}
}
