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

import docking.ActionContext;
import docking.ComponentProvider;
import docking.widgets.tree.GTree;

/**
 * {@link FileSystemBrowserPlugin}-specific action.
 */
public class FSBActionContext extends ActionContext {

	private GTree gTree;

	/**
	 * Creates a new {@link FileSystemBrowserPlugin}-specific action context.
	 * 
	 * @param provider the ComponentProvider that generated this context.
	 * @param contextObject an optional contextObject that the ComponentProvider can provide to the 
	 *   action.
	 * @param gTree {@link FileSystemBrowserPlugin} provider tree.
	 */
	public FSBActionContext(ComponentProvider provider, Object contextObject, GTree gTree) {
		super(provider, contextObject, gTree);
		this.gTree = gTree;
	}

	/**
	 * Gets the {@link FileSystemBrowserPlugin} provider's  tree.
	 * 
	 * @return The {@link FileSystemBrowserPlugin} provider's  tree.
	 */
	public GTree getTree() {
		return gTree;
	}
}
