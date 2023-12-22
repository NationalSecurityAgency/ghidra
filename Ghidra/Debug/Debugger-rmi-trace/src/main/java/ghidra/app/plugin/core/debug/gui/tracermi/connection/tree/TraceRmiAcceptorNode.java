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
import ghidra.debug.api.tracermi.TraceRmiAcceptor;

public class TraceRmiAcceptorNode extends AbstractTraceRmiManagerNode {

	private static final Icon ICON = DebuggerResources.ICON_CONNECT_ACCEPT;

	private final TraceRmiAcceptor acceptor;

	public TraceRmiAcceptorNode(TraceRmiConnectionManagerProvider provider,
			TraceRmiAcceptor acceptor) {
		super(provider, "ACCEPTING: " + acceptor.getAddress());
		this.acceptor = acceptor;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return ICON;
	}

	@Override
	public String getToolTip() {
		return "Trace RMI Acceptor listening at " + acceptor.getAddress();
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	public TraceRmiAcceptor getAcceptor() {
		return acceptor;
	}
}
