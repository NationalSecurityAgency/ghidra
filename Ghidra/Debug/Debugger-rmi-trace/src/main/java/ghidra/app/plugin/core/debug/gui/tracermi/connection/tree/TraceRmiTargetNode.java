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

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider;
import ghidra.debug.api.target.Target;
import resources.MultiIcon;

public class TraceRmiTargetNode extends AbstractTraceRmiManagerNode {
	private static final Icon ICON = DebuggerResources.ICON_RECORD;
	private static final Icon ICON_TX = new MultiIcon(ICON, ICON_TX_OVERLAY);

	private final TraceRmiConnectionNode connectionNode;
	private final Target target;

	public TraceRmiTargetNode(TraceRmiConnectionManagerProvider provider,
			TraceRmiConnectionNode connectionNode, Target target) {
		super(provider, target.getTrace().getName());
		this.connectionNode = connectionNode;
		this.target = target;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return target.isBusy() ? ICON_TX : ICON;
	}

	@Override
	public String getDisplayText() {
		return target.getTrace().getName() + " (snap=" + target.getSnap() + ")";
	}

	@Override
	public String getToolTip() {
		return "Target: " + target.getTrace().getName();
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	public TraceRmiConnectionNode getConnectionNode() {
		return connectionNode;
	}

	public Target getTarget() {
		return target;
	}
}
