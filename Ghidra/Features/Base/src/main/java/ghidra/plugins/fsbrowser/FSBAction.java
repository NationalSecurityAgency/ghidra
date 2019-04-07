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
package ghidra.plugins.fsbrowser;
import docking.action.DockingAction;
import ghidra.framework.plugintool.Plugin;

/**
 * {@link FileSystemBrowserPlugin}-specific action.
 */
public abstract class FSBAction extends DockingAction {

	private final String menuText;

	public FSBAction(String menuText, Plugin plugin) {
		this(menuText, menuText, plugin);
	}

	public FSBAction(String name, String menuText, Plugin plugin) {
		super("FSB " + name, plugin.getName());
		this.menuText = menuText;
	}

	public String getMenuText() {
		return menuText;
	}
}
