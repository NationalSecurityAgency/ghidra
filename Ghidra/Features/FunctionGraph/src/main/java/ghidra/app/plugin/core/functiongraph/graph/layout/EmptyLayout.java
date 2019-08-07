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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import java.awt.Shape;
import java.awt.geom.Point2D;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EmptyLayout extends AbstractVisualGraphLayout<FGVertex, FGEdge> implements FGLayout {

	private static final String NAME = "Empty Layout";

	public EmptyLayout(FunctionGraph graph) {
		super(graph, NAME);
	}

	@Override
	public void initialize() {
		// stub	
	}

	@Override
	public void reset() {
		// stub
	}

	@Override
	public BasicEdgeRenderer<FGVertex, FGEdge> getEdgeRenderer() {
		return new ArticulatedEdgeRenderer<>();
	}

	@Override
	public Function<FGEdge, Shape> getEdgeShapeTransformer() {
		return new ArticulatedEdgeTransformer<>();
	}

	@Override
	protected GridLocationMap<FGVertex, FGEdge> performInitialGridLayout(
			VisualGraph<FGVertex, FGEdge> g) throws CancelledException {

		// Note: this is not called, since we overrode calculateLocations()
		return null;
	}

	@Override
	public LayoutPositions<FGVertex, FGEdge> calculateLocations(VisualGraph<FGVertex, FGEdge> g,
			TaskMonitor taskMonitor) {
		return LayoutPositions.createEmptyPositions();
	}

	@Override
	public AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedLayout(
			VisualGraph<FGVertex, FGEdge> newGraph) {
		return new EmptyLayout((FunctionGraph) newGraph);
	}

	@Override
	public FGLayout cloneLayout(VisualGraph<FGVertex, FGEdge> newGraph) {
		return (FGLayout) super.cloneLayout(newGraph);
	}

	@Override
	public boolean usesEdgeArticulations() {
		return false;
	}

	@Override
	public void setLocation(FGVertex v, Point2D location, ChangeType changeType) {
		// stub
	}

	@Override
	public void addLayoutListener(LayoutListener<FGVertex, FGEdge> listener) {
		// stub
	}

	@Override
	public void removeLayoutListener(LayoutListener<FGVertex, FGEdge> listener) {
		// stub
	}

	@Override
	public void dispose() {
		// stub
	}

	@Override
	public FunctionGraph getVisualGraph() {
		return (FunctionGraph) getGraph();
	}

}
