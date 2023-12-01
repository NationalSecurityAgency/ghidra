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

import java.util.HashMap;
import java.util.Map;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracermi.TraceRmiConnection;

public class TraceRmiConnectionNode extends AbstractTraceRmiManagerNode {
	private static final Icon ICON = DebuggerResources.ICON_CONNECTION;

	private final TraceRmiConnection connection;
	private final Map<Target, TraceRmiTargetNode> targetNodes = new HashMap<>();

	public TraceRmiConnectionNode(TraceRmiConnectionManagerProvider provider,
			TraceRmiConnection connection) {
		// TODO: Can the connector identify/describe itself for this display?
		super(provider, "Connected: " + connection.getRemoteAddress());
		this.connection = connection;
	}

	@Override
	public String getDisplayText() {
		return connection.getDescription() + " at " + connection.getRemoteAddress();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return ICON;
	}

	@Override
	public String getToolTip() {
		return "Trace RMI Connection to " + connection.getDescription() + " at " +
			connection.getRemoteAddress();
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	private TraceRmiTargetNode newTargetNode(Target target) {
		return new TraceRmiTargetNode(provider, this, target);
	}

	private TraceRmiTargetNode addTargetNode(Target target) {
		TraceRmiTargetNode node;
		synchronized (targetNodes) {
			node = targetNodes.computeIfAbsent(target, this::newTargetNode);
		}
		addNode(node);
		return node;
	}

	private void removeTargetNode(Target target) {
		TraceRmiTargetNode node;
		synchronized (targetNodes) {
			node = targetNodes.remove(target);
		}
		if (node == null) {
			return;
		}
		removeNode(node);
	}

	public TraceRmiTargetNode targetPublished(Target target) {
		return addTargetNode(target);
	}

	public void targetWithdrawn(Target target) {
		removeTargetNode(target);
	}

	public TraceRmiConnection getConnection() {
		return connection;
	}
}
