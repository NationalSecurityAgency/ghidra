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
package ghidra.dbg.jdi.model;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import com.sun.jdi.VirtualMachineManager;
import com.sun.jdi.connect.Connector;

import ghidra.async.AsyncFence;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.schema.*;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "ConnectorContainer",
	elements = {
		@TargetElementType(type = JdiModelTargetConnector.class)
	},
	attributes = {
		@TargetAttributeType(type = Void.class)
	},
	canonicalContainer = true)
public class JdiModelTargetConnectorContainer extends JdiModelTargetObjectImpl {

	protected final JdiModelTargetRoot root;

	// TODO: Is it possible to load the same object twice?
	protected final Map<String, JdiModelTargetConnector> connectorsByName = new HashMap<>();
	private JdiModelTargetConnector defaultConnector;

	public JdiModelTargetConnectorContainer(JdiModelTargetRoot root) {
		super(root, "Connectors");
		this.root = root;
	}

	protected CompletableFuture<Void> updateUsingConnectors(Map<String, Connector> byName) {
		List<JdiModelTargetConnector> connectors;
		synchronized (this) {
			connectors =
				byName.values().stream().map(this::getTargetConnector).collect(Collectors.toList());
		}
		AsyncFence fence = new AsyncFence();
		for (JdiModelTargetConnector c : connectors) {
			fence.include(c.init());
		}
		return fence.ready().thenAccept(__ -> {
			changeElements(List.of(), connectors, Map.of(), "Refreshed");
		});
	}

	@Override
	protected CompletableFuture<Void> requestElements(boolean refresh) {
		// Ignore 'refresh' because inferior.getKnownModules may exclude executable
		return doRefresh();
	}

	protected CompletableFuture<Void> doRefresh() {
		Map<String, Connector> map = new HashMap<>();
		VirtualMachineManager vmm = impl.getManager().getVirtualMachineManager();
		List<Connector> allConnectors = vmm.allConnectors();
		for (Connector cx : allConnectors) {
			map.put(cx.name(), cx);
		}
		connectorsByName.keySet().retainAll(map.keySet());
		return updateUsingConnectors(map);
	}

	protected synchronized JdiModelTargetConnector getTargetConnector(Connector cx) {
		return connectorsByName.computeIfAbsent(cx.name(),
			n -> new JdiModelTargetConnector(this, cx, true));
	}

	public synchronized JdiModelTargetConnector getTargetConnectorIfPresent(String name) {
		for (String key : connectorsByName.keySet()) {
			if (key.contains(name)) {
				return connectorsByName.get(key);
			}
		}
		return null;
	}

	public CompletableFuture<?> refreshInternal() {
		if (!isObserved()) {
			return AsyncUtils.NIL;
		}
		return doRefresh().exceptionally(ex -> {
			Msg.error(this, "Problem refreshing inferior's modules", ex);
			return null;
		});
	}

	public JdiModelTargetConnector getDefaultConnector() {
		return defaultConnector;
	}

	public void setDefaultConnector(JdiModelTargetConnector defaultConnector) {
		this.defaultConnector = defaultConnector;
	}

}
