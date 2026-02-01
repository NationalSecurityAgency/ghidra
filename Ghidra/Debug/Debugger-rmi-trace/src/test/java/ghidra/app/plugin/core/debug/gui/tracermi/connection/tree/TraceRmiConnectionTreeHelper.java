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

import java.util.Map;

import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracermi.TraceRmiAcceptor;
import ghidra.debug.api.tracermi.TraceRmiConnection;

public class TraceRmiConnectionTreeHelper {
	public static Map<TraceRmiAcceptor, TraceRmiAcceptorNode> getAcceptorNodeMap(
			TraceRmiServiceNode serviceNode) {
		return serviceNode.acceptorNodes;
	}

	public static Map<TraceRmiConnection, TraceRmiConnectionNode> getConnectionNodeMap(
			TraceRmiServiceNode serviceNode) {
		return serviceNode.connectionNodes;
	}

	public static Map<Target, TraceRmiTargetNode> getTargetNodeMap(
			TraceRmiServiceNode serviceNode) {
		return serviceNode.targetNodes;
	}

	public static TraceRmiServerNode getServerNode(TraceRmiServiceNode serviceNode) {
		return serviceNode.serverNode;
	}
}
