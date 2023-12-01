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
package ghidra.app.plugin.core.debug.gui.tracermi.connection;

import javax.swing.tree.TreePath;

import docking.DefaultActionContext;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.tree.TraceRmiManagerNode;

public class TraceRmiManagerActionContext extends DefaultActionContext {
	private final TreePath path;

	public TraceRmiManagerActionContext(TraceRmiConnectionManagerProvider provider,
			TreePath path, GTree tree) {
		super(provider, path, tree);
		this.path = path;
	}

	public TraceRmiManagerNode getSelectedNode() {
		if (path == null) {
			return null;
		}
		return (TraceRmiManagerNode) path.getLastPathComponent();
	}
}
