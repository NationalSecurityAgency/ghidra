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
package ghidra.app.plugin.core.functiongraph.graph;

import java.awt.geom.Point2D;
import java.util.*;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.program.model.symbol.FlowType;

public class FGEdgeImpl implements FGEdge {

	private final FGVertex startVertex;
	private final FGVertex destinationVertex;
	private final FlowType flowType;
	private final FunctionGraphOptions options;

	private List<Point2D> layoutArticulationPoints = new ArrayList<>();

	boolean doHashCode = true;
	int hashCode;

	private boolean inHoveredPath = false;
	private boolean inFocusedPath = false;
	private boolean selected = false;
	private double emphasis = 0D;
	private double defaultAlpha = 1D;
	private double alpha = defaultAlpha;
	private String edgeLabel = null;

	public FGEdgeImpl(FGVertex startVertex, FGVertex destinationVertex, FlowType flowType,
			FunctionGraphOptions options) {
		this.options = options;
		this.startVertex = Objects.requireNonNull(startVertex, "Edge start vertex cannot be null");
		this.destinationVertex =
			Objects.requireNonNull(destinationVertex, "Edge end vertex cannot be null");
		this.flowType = flowType;
	}

	@Override
	public boolean isInHoveredVertexPath() {
		return inHoveredPath;
	}

	@Override
	public boolean isInFocusedVertexPath() {
		return inFocusedPath;
	}

	@Override
	public void setInHoveredVertexPath(boolean inPath) {
		this.inHoveredPath = inPath;
	}

	@Override
	public void setInFocusedVertexPath(boolean inPath) {
		this.inFocusedPath = inPath;
	}

	@Override
	public boolean isSelected() {
		return selected;
	}

	@Override
	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	@Override
	public double getEmphasis() {
		return emphasis;
	}

	@Override
	public void setEmphasis(double emphasis) {
		this.emphasis = emphasis;
	}

	@Override
	public void setAlpha(double alpha) {
		this.alpha = alpha;
	}

	@Override
	public double getAlpha() {
		return alpha;
	}

	@Override
	public void setDefaultAlpha(double alpha) {
		this.defaultAlpha = alpha;
		this.alpha = alpha;
	}

	@Override
	public double getDefaultAlpha() {
		return defaultAlpha;
	}

	@Override
	public List<Point2D> getArticulationPoints() {
		return layoutArticulationPoints;
	}

	@Override
	public void setArticulationPoints(List<Point2D> layoutArticulationPoints) {
		if (layoutArticulationPoints == null) {
			this.layoutArticulationPoints = Collections.emptyList();
		}
		else {
			this.layoutArticulationPoints = Collections.unmodifiableList(layoutArticulationPoints);
		}

	}

	@Override
	public FGVertex getStart() {
		return startVertex;
	}

	@Override
	public FGVertex getEnd() {
		return destinationVertex;
	}

	@Override
	public FlowType getFlowType() {
		return flowType;
	}

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public FGEdgeImpl cloneEdge(FGVertex newStartVertex, FGVertex newDestinationVertex) {

		FGEdgeImpl newEdge =
			new FGEdgeImpl(newStartVertex, newDestinationVertex, flowType, options);

		List<Point2D> newPoints = new ArrayList<>(layoutArticulationPoints.size());
		for (Point2D point : layoutArticulationPoints) {
			newPoints.add((Point2D) point.clone());
		}
		newEdge.layoutArticulationPoints = newPoints;

		newEdge.alpha = alpha;
		newEdge.defaultAlpha = defaultAlpha;
		newEdge.inHoveredPath = inHoveredPath;
		newEdge.inFocusedPath = inFocusedPath;
		newEdge.selected = selected;
		return newEdge;
	}

	@Override
	public String getLabel() {
		return edgeLabel;
	}

	@Override
	public void setLabel(String label) {
		this.edgeLabel = label;
	}

//==================================================================================================
// Overridden Default Methods
//==================================================================================================	

	@Override
	public int hashCode() {
		if (doHashCode) {
			final int destHashCode = destinationVertex.hashCode();
			final int rearranged = destHashCode >> 16 | (destHashCode << 16);
			hashCode = startVertex.hashCode() ^ rearranged;
			doHashCode = false;
		}
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		FGEdgeImpl other = (FGEdgeImpl) obj;
		return startVertex.equals(other.startVertex) &&
			destinationVertex.equals(other.destinationVertex) && flowType.equals(other.flowType);
	}

	@Override
	public String toString() {
		return "(" + getStart() + " -> " + getEnd() + ")";
	}

}
