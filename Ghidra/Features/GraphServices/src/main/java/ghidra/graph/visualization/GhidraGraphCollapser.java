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
package ghidra.graph.visualization;

import java.util.*;

import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.selection.MutableSelectedState;
import org.jungrapht.visualization.sublayout.VisualGraphCollapser;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * Handles collapsing graph nodes. Had to subclass because the GroupVertex supplier needed
 * access to the items it contain at creation time.
 */
public class GhidraGraphCollapser extends VisualGraphCollapser<AttributedVertex, AttributedEdge> {

	public GhidraGraphCollapser(VisualizationServer<AttributedVertex, AttributedEdge> vv) {
		super(vv);
	}

	/**
	 * Ungroups any GroupVertices that are selected
	 */
	public void ungroupSelectedVertices() {
		expand(vv.getSelectedVertices());
	}

	/**
	 * Group the selected vertices into one vertex that represents them all
	 * 
	 * @return the new GroupVertex
	 */
	public AttributedVertex groupSelectedVertices() {
		MutableSelectedState<AttributedVertex> selectedVState = vv.getSelectedVertexState();
		MutableSelectedState<AttributedEdge> selectedEState = vv.getSelectedEdgeState();
		Collection<AttributedVertex> selected = selectedVState.getSelected();
		if (selected.size() > 1) {
			AttributedVertex groupVertex = collapse(selected, s -> GroupVertex.groupVertices(selected));
			selectedVState.clear();
			selectedEState.clear();
			selectedVState.select(groupVertex);
			return groupVertex;
		}
		return null;
	}

	/**
	 * Converts the given set of vertices to a new set where any vertices that are part of a group
	 * are replaced with the outermost group containing it.
	 *  
	 * @param vertices the set of vertices to possibly convert to containing group nodes
	 * @return a converted set of vertices where all vertices part of a group have been replace with
	 * its containing outermost GroupNode.
	 */
	public Set<AttributedVertex> convertToOutermostVertices(Set<AttributedVertex> vertices) {
		Set<AttributedVertex> set = new HashSet<>();
		for (AttributedVertex v : vertices) {
			set.add(getOutermostVertex(v));
		}
		return set;
	}

	/**
	 * Return the outermost GroupVertex containing the given vertex or else return the given vertex
	 * if it is not in a group.	 
	 *  
	 * @param vertex the vertex to check if inside a group.
	 * @return the outermost GroupVertex containing the given vertex or else return the given vertex
	 * if it is not in a group.
	 */
	public AttributedVertex getOutermostVertex(AttributedVertex vertex) {
		while (!graph.containsVertex(vertex)) {
			AttributedVertex owner = findOwnerOf(vertex);
			if (owner == null) {
				break;  // should never happen. not sure what to do here, but don't want to loop forever
			}
			vertex = owner;
		}
		return vertex;
	}
}
