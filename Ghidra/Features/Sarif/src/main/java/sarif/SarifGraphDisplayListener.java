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
package sarif;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import docking.widgets.EventTrigger;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramLocation;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayListener;

/**
 * {@link GraphDisplayListener} that handle events back and from from program
 * graphs.
 */
public class SarifGraphDisplayListener extends AddressBasedGraphDisplayListener {

	private Map<Address, Set<AttributedVertex>> map = new HashMap<>();
	private SarifController controller;
	private AttributedGraph graph;

	public SarifGraphDisplayListener(SarifController controller, GraphDisplay display, AttributedGraph graph) {
		super(controller.getPlugin().getTool(), controller.getProgram(), display);
		this.controller = controller;
		this.graph = graph;
		for (AttributedVertex vertex : graph.vertexSet()) {
			String addrStr = vertex.getAttribute("Address");
			if (addrStr != null) {
				Address address = program.getAddressFactory().getAddress(addrStr);
				Set<AttributedVertex> set = map.get(address);
				if (set == null) {
					set = new HashSet<>();
				}
				set.add(vertex);
				map.put(address, set);
			}
		}
	}

	@Override
	public void eventSent(PluginEvent event) {
		super.eventSent(event);
		if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent ev = (ProgramLocationPluginEvent) event;
			if (program.equals(ev.getProgram())) {
				ProgramLocation location = ev.getLocation();
				Set<AttributedVertex> vertices = getVertices(location.getAddress());
				if (vertices != null) {
					graphDisplay.selectVertices(vertices, EventTrigger.INTERNAL_ONLY);
				}
			}
		}
	}

	@Override
	public void selectionChanged(Set<AttributedVertex> vertices) {
		super.selectionChanged(vertices);
		controller.setSelection(vertices);
	}
	
	@Override
	public Address getAddress(AttributedVertex vertex) {
		String addrStr = vertex.getAttribute("Address");
		Address address = program.getAddressFactory().getAddress(addrStr);
		return address;
	}

	protected Set<AttributedVertex> getVertices(Address address) {
		return map.get(address);
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView addrSet) {
		if (addrSet.isEmpty()) {
			return Collections.emptySet();
		}

		Set<AttributedVertex> vertices = new HashSet<>();
		for (Entry<Address, Set<AttributedVertex>> entry : map.entrySet()) {
			if (addrSet.contains(entry.getKey())) {
				for (AttributedVertex v : entry.getValue()) {
					vertices.add(v);
				}
			}
		}
		return vertices;
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertices) {

		AddressSet addrSet = new AddressSet();
		Collection<Set<AttributedVertex>> values = map.values();
		for (Set<AttributedVertex> set : values) {
			for (AttributedVertex vertex : vertices) {
				if (set.contains(vertex)) {
					String addrStr = vertex.getAttribute("Address");
					Address address = program.getAddressFactory().getAddress(addrStr);
					addrSet.add(address);
				}
			}
		}
		return addrSet;
	}

	protected boolean isValidAddress(Address addr) {
		if (addr == null || program == null) {
			return false;
		}
		return program.getMemory().contains(addr) || addr.isExternalAddress();
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay newGraphDisplay) {
		return new SarifGraphDisplayListener(controller, newGraphDisplay, graph);
	}

}
