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
package ghidra.app.plugin.core.functiongraph;

import ghidra.app.nav.LocationMemento;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.framework.options.SaveState;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class FGLocationMemento extends LocationMemento {
	private GraphPerspectiveInfo<FGVertex, FGEdge> info;

	FGLocationMemento(Program program, ProgramLocation location,
			GraphPerspectiveInfo<FGVertex, FGEdge> info) {
		super(program, location);
		this.info = info;
	}

	public FGLocationMemento(SaveState saveState, Program[] programs) {
		super(saveState, programs);
		info = new GraphPerspectiveInfo<>(saveState);
	}

	@Override
	public void saveState(SaveState saveState) {
		super.saveState(saveState);
		info.saveState(saveState);
	}

	GraphPerspectiveInfo<FGVertex, FGEdge> getGraphPerspectiveInfo() {
		return info;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "FG Memento [\n\tperspective=" + info +
				",\n\taddress=" + programLocation.getAddress() + 
				",\n\tlocation=" + programLocation + 
				"\n]";
		//@formatter:on
	}
}
