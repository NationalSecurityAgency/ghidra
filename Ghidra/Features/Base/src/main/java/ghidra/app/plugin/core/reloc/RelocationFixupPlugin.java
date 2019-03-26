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
package ghidra.app.plugin.core.reloc;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.classfinder.ClassSearcher;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Attempts to fix up relocations when a program's image base is changed",
	description = "Listens for image base changes and attempts to fix up relocations."
			+ "It searches for relocation algorithms based on format and relocation type."
)
//@formatter:on
public class RelocationFixupPlugin extends ProgramPlugin implements DomainObjectListener {
	private List<RelocationFixupHandler> relocationHandlerList =
		new ArrayList<RelocationFixupHandler>();

	public RelocationFixupPlugin(PluginTool tool) {
		super(tool, false, false);

		initializeRelocationHandlers();

	}

	private void initializeRelocationHandlers() {
		relocationHandlerList.addAll(ClassSearcher.getInstances(RelocationFixupHandler.class));
	}

	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!ev.containsEvent(ChangeManager.DOCR_IMAGE_BASE_CHANGED)) {
			return;
		}
		for (DomainObjectChangeRecord record : ev) {
			if (record.getEventType() == ChangeManager.DOCR_IMAGE_BASE_CHANGED) {
				Address oldImageBase = (Address) record.getOldValue();
				Address newImageBase = (Address) record.getNewValue();
				imageBaseChanged(oldImageBase, newImageBase);
			}
		}
	}

	private void imageBaseChanged(Address oldImageBase, Address newImageBase) {
		RelocationFixupHandler handler = findRelocationHandler();

		RelocationFixupCommand relocationFixupCommand =
			new RelocationFixupCommand(handler, oldImageBase, newImageBase);

		tool.executeBackgroundCommand(relocationFixupCommand, currentProgram);

	}

	private RelocationFixupHandler findRelocationHandler() {
		for (RelocationFixupHandler handler : relocationHandlerList) {
			if (handler.handlesProgram(currentProgram)) {
				return handler;
			}
		}
		return null;
	}
}
