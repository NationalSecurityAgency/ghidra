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
package ghidra.app.plugin.core.decompile.actions;

import java.util.Collections;
import java.util.Set;

import ghidra.app.plugin.core.graph.AddressBasedGraphDisplayListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.service.graph.*;

/**
 * GraphDisplayListener for a PCode data flow graph
 */
class PCodeDfgDisplayListener extends AddressBasedGraphDisplayListener {

	HighFunction highfunc;

	public PCodeDfgDisplayListener(PluginTool tool, GraphDisplay display, HighFunction high,
			Program program) {
		super(tool, program, display);
		highfunc = high;
	}

	@Override
	protected Set<AttributedVertex> getVertices(AddressSetView selection) {
		return Collections.emptySet();
	}

	@Override
	protected AddressSet getAddresses(Set<AttributedVertex> vertices) {
		AddressSet set = new AddressSet();
		for (AttributedVertex vertex : vertices) {
			Address address = getAddress(vertex);
			if (address != null) {
				set.add(address);
			}
		}
		return set;
	}

	@Override
	protected Address getAddress(AttributedVertex vertex) {
		if (vertex == null) {
			return null;
		}
		String vertexId = vertex.getId();
		int firstColon = vertexId.indexOf(':');
		if (firstColon == -1) {
			return null;
		}

		int firstSpace = vertexId.indexOf(' ');
		String addrString = vertexId.substring(0, firstSpace);
		return getAddress(addrString);
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay display) {
		return new PCodeDfgDisplayListener(tool, display, highfunc, program);
	}
}
