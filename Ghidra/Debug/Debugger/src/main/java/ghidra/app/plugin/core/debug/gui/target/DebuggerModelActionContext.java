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
package ghidra.app.plugin.core.debug.gui.target;

import java.util.function.Function;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerObjectModel;

public class DebuggerModelActionContext extends ActionContext {
	private final TreePath path;

	DebuggerModelActionContext(ComponentProvider provider, TreePath path, GTree tree) {
		super(provider, path, tree);
		this.path = path;
	}

	protected <T extends GTreeNode, U> U getIf(Class<T> cls, Function<T, U> getter) {
		if (path == null) {
			return null;
		}
		Object last = path.getLastPathComponent();
		if (!cls.isAssignableFrom(last.getClass())) {
			return null;
		}
		T node = cls.cast(last);
		return getter.apply(node);
	}

	public DebuggerModelService getIfModelService() {
		return getIf(DebuggerConnectionsNode.class, DebuggerConnectionsNode::getTargetService);
	}

	public DebuggerObjectModel getIfDebuggerModel() {
		return getIf(DebuggerModelNode.class, DebuggerModelNode::getDebuggerModel);
	}
}
