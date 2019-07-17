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
package ghidra.framework.plugintool;

import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.util.PluginClassManager;

/**
 * PluginTool that is used by the Merge process to resolve conflicts
 * when a file is being checked into a server repository. This tool
 * is modal while it is visible.
 * 
 */
public class ModalPluginTool extends PluginTool {

	public static ModalPluginTool createTool(String name) {
		Project project = AppInfo.getActiveProject();
		if (project == null) {
			return new ModalPluginTool(name);
		}
		return new ModalPluginTool(project, name);
	}

	private ModalPluginTool(Project project, String name) {
		super(project, name, false, true, true);
	}

	private ModalPluginTool(String name) {
		super(null, null, null, name, false, true, true);
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		return null;
	}
}
