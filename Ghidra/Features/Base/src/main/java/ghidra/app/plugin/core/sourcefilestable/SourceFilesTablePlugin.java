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
package ghidra.app.plugin.core.sourcefilestable;

import static ghidra.program.util.ProgramEvent.*;

import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Source File Table",
	description = "Plugin for viewing and managing source file information.",
	eventsConsumed = { ProgramClosedPluginEvent.class }
)
//@formatter:on

/**
 * A {@link ProgramPlugin} for displaying source file information about a program
 * and for managing source file path transforms.
 */
public class SourceFilesTablePlugin extends ProgramPlugin {

	private SourceFilesTableProvider provider;
	private DomainObjectListener listener;

	/**
	 * Constructor
	 * @param plugintool tool
	 */
	public SourceFilesTablePlugin(PluginTool plugintool) {
		super(plugintool);
	}

	@Override
	public void init() {
		super.init();
		provider = new SourceFilesTableProvider(this);
		listener = createDomainObjectListener();
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(listener);
		provider.programActivated(program);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(listener);
		provider.clearTableModels();
	}

	@Override
	protected void dispose() {
		if (currentProgram != null) {
			currentProgram.removeListener(listener);
		}
		tool.removeComponentProvider(provider);
	}

	private DomainObjectListener createDomainObjectListener() {
		// @formatter:off
		return new DomainObjectListenerBuilder(this)
			.ignoreWhen(() -> !provider.isVisible())
			.any(DomainObjectEvent.RESTORED, MEMORY_BLOCK_MOVED, MEMORY_BLOCK_REMOVED)
			.terminate(c -> provider.setIsStale(true))
			.with(ProgramChangeRecord.class)
			.each(SOURCE_FILE_ADDED,SOURCE_FILE_REMOVED,SOURCE_MAP_CHANGED)
			.call(provider::handleProgramChange)
			.build();
		// @formatter:on
	}
}
