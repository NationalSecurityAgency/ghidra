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
package ghidra.app.plugin.core.debug.service.emulation;

import java.util.List;
import java.util.stream.Stream;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

public abstract class AbstractEmulateAction extends DockingAction {
	final DebuggerEmulationServicePlugin plugin;
	final PluginTool tool;
	final String compressedPath;
	protected Program program;

	public AbstractEmulateAction(DebuggerEmulationServicePlugin plugin, String name) {
		this(plugin, name, null);
	}

	public AbstractEmulateAction(DebuggerEmulationServicePlugin plugin, String name,
			Program program) {
		super(name, plugin.getName());
		this.plugin = plugin;
		this.tool = plugin.getTool();
		this.program = program;
		MenuData menuData = computeMenuData();
		setPopupMenuData(menuData);
		String path = menuData.getMenuPathAsString();
		compressedPath = path.replaceAll("\\.\\.\\.->", "").toLowerCase();
	}

	protected static String[] prependMenuPath(String pre, List<String> menuPath) {
		return Stream.concat(Stream.of(pre), menuPath.stream()).toArray(String[]::new);
	}

	abstract MenuData computeMenuData();

	String getTopGroup(Program currentProgram) {
		return "";
	}

	String getTopOrder(Program currentProgram) {
		return "";
	}

	public String getCompressedPath() {
		return compressedPath;
	}

	protected Program getProgramFromContext(ActionContext context) {
		if (context instanceof ProgramLocationActionContext plctx) {
			return plctx.getProgram();
		}
		return program;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public abstract void actionPerformed(ActionContext context);

	@Override
	public abstract HelpLocation getHelpLocation();

	protected ProgramLocation getCurrentLocation() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		if (service == null) {
			return null;
		}
		return service.getCurrentLocation();
	}

	protected Address getCurrentAddress() {
		ProgramLocation currentLocation = getCurrentLocation();
		if (currentLocation == null) {
			return null;
		}
		return currentLocation.getAddress();
	}

}
