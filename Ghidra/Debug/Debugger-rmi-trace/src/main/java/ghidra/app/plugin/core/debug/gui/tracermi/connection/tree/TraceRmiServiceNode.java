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

import java.net.SocketAddress;
import java.util.*;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.tracermi.connection.TraceRmiConnectionManagerProvider;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.target.TargetPublicationListener;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.*;
import ghidra.util.Msg;

public class TraceRmiServiceNode extends AbstractTraceRmiManagerNode
		implements TraceRmiServiceListener, TargetPublicationListener {
	private static final String DESCRIPTION = "The TraceRmi service";

	final TraceRmiServerNode serverNode;
	final Map<TraceRmiConnection, TraceRmiConnectionNode> connectionNodes = new HashMap<>();
	final Map<TraceRmiAcceptor, TraceRmiAcceptorNode> acceptorNodes = new HashMap<>();
	// weak because each connection node keeps the strong map
	final Map<Target, TraceRmiTargetNode> targetNodes = new WeakHashMap<>();

	public TraceRmiServiceNode(TraceRmiConnectionManagerProvider provider) {
		super(provider, "<root>");
		this.serverNode = new TraceRmiServerNode(provider);

		addNode(serverNode);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getToolTip() {
		return DESCRIPTION;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	private TraceRmiConnectionNode newConnectionNode(TraceRmiConnection connection) {
		return new TraceRmiConnectionNode(provider, connection);
	}

	private void addConnectionNode(TraceRmiConnection connection) {
		TraceRmiConnectionNode node;
		synchronized (connectionNodes) {
			node = connectionNodes.computeIfAbsent(connection, this::newConnectionNode);
		}
		addNode(node);
	}

	private void removeConnectionNode(TraceRmiConnection connection) {
		TraceRmiConnectionNode node;
		synchronized (connectionNodes) {
			node = connectionNodes.remove(connection);
		}
		if (node == null) {
			return;
		}
		removeNode(node);
	}

	private TraceRmiAcceptorNode newAcceptorNode(TraceRmiAcceptor acceptor) {
		return new TraceRmiAcceptorNode(provider, acceptor);
	}

	private void addAcceptorNode(TraceRmiAcceptor acceptor) {
		TraceRmiAcceptorNode node;
		synchronized (acceptorNodes) {
			node = acceptorNodes.computeIfAbsent(acceptor, this::newAcceptorNode);
		}
		addNode(node);
	}

	private void removeAcceptorNode(TraceRmiAcceptor acceptor) {
		TraceRmiAcceptorNode node;
		synchronized (acceptorNodes) {
			node = acceptorNodes.remove(acceptor);
		}
		if (node == null) {
			return;
		}
		removeNode(node);
	}

	@Override
	public void serverStarted(SocketAddress address) {
		serverNode.fireNodeChanged();
		provider.contextChanged();
	}

	@Override
	public void serverStopped() {
		serverNode.fireNodeChanged();
		provider.contextChanged();
	}

	@Override
	public void connected(TraceRmiConnection connection, ConnectMode mode,
			TraceRmiAcceptor acceptor) {
		addConnectionNode(connection);
		removeAcceptorNode(acceptor);
		provider.contextChanged();
	}

	@Override
	public void disconnected(TraceRmiConnection connection) {
		removeConnectionNode(connection);
		provider.contextChanged();
	}

	@Override
	public void waitingAccept(TraceRmiAcceptor acceptor) {
		addAcceptorNode(acceptor);
		provider.contextChanged();
	}

	@Override
	public void acceptCancelled(TraceRmiAcceptor acceptor) {
		removeAcceptorNode(acceptor);
		provider.contextChanged();
	}

	@Override
	public void acceptFailed(TraceRmiAcceptor acceptor, Exception e) {
		removeAcceptorNode(acceptor);
		provider.contextChanged();
	}

	@Override
	public void targetPublished(TraceRmiConnection connection, Target target) {
		TraceRmiConnectionNode cxNode;
		synchronized (connectionNodes) {
			cxNode = connectionNodes.get(connection);
		}
		if (cxNode == null) {
			Msg.warn(this,
				"Target published on a connection I don't have! " + connection + " " + target);
			return;
		}
		TraceRmiTargetNode tNode = cxNode.targetPublished(target);
		if (tNode == null) {
			return;
		}
		synchronized (targetNodes) {
			targetNodes.put(target, tNode);
		}
		provider.contextChanged();
	}

	@Override
	public void targetPublished(Target target) {
		// Dont care. Using targetPublished(connection, target) instead
	}

	@Override
	public void targetWithdrawn(Target target) {
		TraceRmiTargetNode node;
		synchronized (targetNodes) {
			node = targetNodes.remove(target);
		}
		if (node == null) {
			return;
		}
		node.getConnectionNode().targetWithdrawn(target);
		provider.contextChanged();
	}

	public void coordinates(DebuggerCoordinates coordinates) {
		Target target = coordinates.getTarget();
		if (target == null) {
			return;
		}
		TraceRmiTargetNode node;
		synchronized (targetNodes) {
			node = targetNodes.get(target);
		}
		if (node == null) {
			return;
		}
		node.fireNodeChanged();
	}
}
