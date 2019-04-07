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
package ghidra.graph.viewer;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.awt.Rectangle;

import org.junit.Test;

import ghidra.graph.graphs.*;
import ghidra.graph.support.TestVisualGraph;
import ghidra.util.Msg;

public class VisualGraphViewUpdaterTest extends AbstractVisualGraphTest {

	@Override
	protected TestVisualGraph buildGraph() {

		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		AbstractTestVertex v3 = new LabelTestVertex("3");
		TestEdge e1 = new TestEdge(v1, v2);
		TestEdge e2 = new TestEdge(v2, v3);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addVertex(v3);
		g.addEdge(e1);
		g.addEdge(e2);

		return g;
	}

	@Test
	public void testEnsureVertexVisible() {

		AbstractTestVertex v = getVertex("1");
		moveVertex(v, 500, 0); // move offscreen
		assertVertexHidden(v);

		ensureVertexVisible(v);
		assertVertexNotHidden(v);
	}

	private void assertVertexNotHidden(AbstractTestVertex v) {

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Rectangle vertexBounds = getBounds(v);
		Rectangle viewerBounds = viewer.getBounds();
		assertTrue(viewerBounds.contains(vertexBounds));

		SatelliteGraphViewer<AbstractTestVertex, TestEdge> satelliteViewer =
			graphComponent.getSatelliteViewer();
		Rectangle satelliteBounds = satelliteViewer.getBounds();
		assertFalse(satelliteBounds.intersects(vertexBounds));
	}

	private void assertVertexHidden(AbstractTestVertex v) {

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Rectangle vertexBounds = getBounds(v);
		Rectangle viewerBounds = viewer.getBounds();

		if (viewerBounds.intersects(vertexBounds)) {
			Msg.debug(this, "vertex bounds should not be in viewer bounds\n\tvertex bounds: " +
				vertexBounds + "\n\tviewer bounds: " + viewerBounds);
		}
		assertFalse(viewerBounds.intersects(vertexBounds));
	}

	private Rectangle getBounds(AbstractTestVertex v) {
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		return swing(() -> GraphViewerUtils.getVertexBoundsInViewSpace(viewer, v));
	}
}
