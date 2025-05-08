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
package ghidra.app.plugin.core.debug.gui.tracermi.connection.tree;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider;

public abstract class AbstractTraceRmiManagerNode extends GTreeNode implements TraceRmiManagerNode {
	protected static final Icon ICON_TX_OVERLAY = new GIcon("icon.debugger.overlay.tx");
	protected final TraceRmiConnectionManagerProvider provider;
	protected final String name;

	public AbstractTraceRmiManagerNode(TraceRmiConnectionManagerProvider provider, String name) {
		this.provider = provider;
		this.name = name;
	}

	@Override
	public String getName() {
		return name;
	}
}
