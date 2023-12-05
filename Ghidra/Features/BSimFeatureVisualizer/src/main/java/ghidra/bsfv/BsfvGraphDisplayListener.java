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
package ghidra.bsfv;

import java.util.HashSet;
import java.util.Set;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.*;

/**
 * This class is the {@link AddressBasedGraphDisplayListener} for translating between vertices of 
 * the BSim feature graphs and Ghidra addresses.
 */
public class BsfvGraphDisplayListener extends AddressBasedGraphDisplayListener {

	/**
	 * Creates a BSimFeatureGraphDisplayListener used to translate between vertices of a BSim 
	 * feature graph and Ghidra addresses
	 * @param tool tool containing the bsim feature visualizer plugin
	 * @param program source of BSim features
	 * @param display graph display for showing the feature graphs
	 */
	public BsfvGraphDisplayListener(PluginTool tool, Program program, GraphDisplay display) {
		super(tool, program, display);
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay gDisplay) {
		return new BsfvGraphDisplayListener(tool, program, gDisplay);
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView selection) {
		Set<AttributedVertex> vertices = new HashSet<>();
		AddressFactory addrFactory = program.getAddressFactory();
		for (AttributedVertex v : graphDisplay.getGraph().vertexSet()) {
			if (v.hasAttribute(BSimFeatureGraphType.OP_ADDRESS)) {
				Address opAddr =
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.OP_ADDRESS));
				if (selection.contains(opAddr)) {
					vertices.add(v);
				}
			}
			if (v.hasAttribute(BSimFeatureGraphType.BLOCK_START) &&
				v.hasAttribute(BSimFeatureGraphType.BLOCK_STOP)) {
				Address start =
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.BLOCK_START));
				Address stop =
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.BLOCK_STOP));
				if (selection.intersects(start, stop)) {
					vertices.add(v);
				}
			}
		}
		return vertices;
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertexIds) {
		AddressSet addresses = new AddressSet();
		AddressFactory addrFactory = program.getAddressFactory();
		for (AttributedVertex v : vertexIds) {
			if (v.hasAttribute(BSimFeatureGraphType.OP_ADDRESS)) {
				addresses.add(
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.OP_ADDRESS)));
			}
			if (v.hasAttribute(BSimFeatureGraphType.BLOCK_START) &&
				v.hasAttribute(BSimFeatureGraphType.BLOCK_STOP)) {
				Address start =
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.BLOCK_START));
				Address stop =
					addrFactory.getAddress(v.getAttribute(BSimFeatureGraphType.BLOCK_STOP));
				addresses.add(start, stop);
			}
		}
		return addresses;
	}

	@Override
	protected Address getAddress(AttributedVertex vertex) {
		AddressFactory addrFactory = program.getAddressFactory();
		if (vertex.hasAttribute(BSimFeatureGraphType.OP_ADDRESS)) {
			return addrFactory.getAddress(vertex.getAttribute(BSimFeatureGraphType.OP_ADDRESS));
		}
		if (vertex.hasAttribute(BSimFeatureGraphType.BLOCK_START)) {
			return addrFactory.getAddress(vertex.getAttribute(BSimFeatureGraphType.BLOCK_START));
		}
		return null;
	}

}
