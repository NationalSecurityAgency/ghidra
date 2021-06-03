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
package ghidra.graph.viewer.edge;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import ghidra.graph.graphs.*;
import ghidra.graph.support.TestVisualGraph;
import ghidra.graph.viewer.AbstractVisualGraphTest;
import ghidra.graph.viewer.PathHighlightMode;
import util.CollectionUtils;

/**
 * A test meant to exercise most of the code paths inside of {@link VisualGraphPathHighlighter}.
 * These tests are not validating the actual correctness of the path calculation, as that work
 * is being done by the various graph algorithm tests.
 */
// Note: this test didn't need to have a UI, but it seemed like it would be nice to have for
//       debugging
public class VisualGraphPathHighlighterTest extends AbstractVisualGraphTest {

	@Override
	protected TestVisualGraph buildGraph() {

		// each test will populate the graph as needed 
		TestVisualGraph g = new TestVisualGraph();
		return g;
	}

	@Override
	protected void initialize() {
		installMouseDebugger();
	}

	@Test
	public void testEdgeFocusMode_IN() {

		/*		  
		  		   v1
		           |
		 		   v2
				 / |
		        /  | 
		      v3   v4
		       \   |
		        \  |
		         - v5
		           |
		           |
		           v6		  
		  
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		focusMode(PathHighlightMode.IN);

		focusVertex(v(1));
		assertNoEdgesInFocusedPath();

		focusVertex(v(6));
		assertAllEdgesInFocusedPath();
	}

	@Test
	public void testEdgeFocusMode_OUT() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		focusMode(PathHighlightMode.OUT);

		focusVertex(v(1));
		assertAllEdgesInFocusedPath();

		focusVertex(v(6));
		assertNoEdgesInFocusedPath();
	}

	@Test
	public void testEdgeFocusMode_INOUT() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		focusMode(PathHighlightMode.INOUT);

		focusVertex(v(1));
		assertAllEdgesInFocusedPath();

		focusVertex(v(6));
		assertAllEdgesInFocusedPath();
	}

	@Test
	public void testEdgeFocusMode_CYCLE() {

		/*		  
			v1 --> v2 --> v3 --> v4 --> v5 --> v6		  
			       ^      |      ^      |
			       | - <--.      | - <--.
			   
			       cycle 1       cycle 2
		 */

		edge(1, 2);
		edge(2, 3);
		edge(3, 2);
		edge(3, 4);
		edge(4, 5);
		edge(5, 4);
		edge(5, 6);

		focusMode(PathHighlightMode.CYCLE);

		focusVertex(v(1));
		assertNoEdgesInFocusedPath();

		focusVertex(v(2));

		//@formatter:off
		assertInFocusedPath(edge(2, 3),
					   edge(3, 2));
		//@formatter:on
	}

	@Test
	public void testEdgeFocusMode_ALLCYCLE() {

		/*		  
		v1 --> v2 --> v3 --> v4 --> v5 --> v6		  
		       ^      |      ^      |
		       | - <--.      | - <--.
		   
		       cycle 1       cycle 2
		*/

		edge(1, 2);
		edge(2, 3);
		edge(3, 2);
		edge(3, 4);
		edge(4, 5);
		edge(5, 4);
		edge(5, 6);

		focusMode(PathHighlightMode.ALLCYCLE);

		//@formatter:off
		assertInFocusedPath(edge(2, 3),
			   		   edge(3, 2), 
			   		   edge(4, 5),
			   		   edge(5, 4));
		//@formatter:on

		// not change with a focused vertex
		focusVertex(v(1));

		//@formatter:off
		assertInFocusedPath(edge(2, 3),
			   		   edge(3, 2), 
			   		   edge(4, 5),
			   		   edge(5, 4));
		//@formatter:on
	}

	@Test
	public void testEdgeFocusMode_SCOPED_FORWARD() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		focusMode(PathHighlightMode.SCOPED_FORWARD);

		focusVertex(v(1));
		assertAllEdgesInFocusedPath();

		focusVertex(v(6));
		assertNoEdgesInFocusedPath();

		focusVertex(v(5));
		assertInFocusedPath(edge(v(5), v(6)));
	}

	@Test
	public void testEdgeFocusMode_SCOPED_REVERSE() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		focusMode(PathHighlightMode.SCOPED_REVERSE);

		focusVertex(v(1));
		assertNoEdgesInFocusedPath();

		focusVertex(v(6));
		assertAllEdgesInFocusedPath();

		focusVertex(v(2));
		assertInFocusedPath(edge(v(1), v(2)));
	}

	@Test
	public void testEdgeHoverMode_IN() {

		/*		  
		   		v1
		        |
				v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		*/

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.IN);

		hoverVertex(v(1));
		assertNoEdgesHovered();

		hoverVertex(v(6));
		assertAllEdgesHovered();
	}

	@Test
	public void testEdgeHoverMode_OUT() {
		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.OUT);

		hoverVertex(v(1));
		assertAllEdgesHovered();

		hoverVertex(v(6));
		assertNoEdgesHovered();
	}

	@Test
	public void testEdgeHoverMode_INOUT() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.INOUT);

		hoverVertex(v(1));
		assertAllEdgesHovered();

		hoverVertex(v(6));
		assertAllEdgesHovered();
	}

	@Test
	public void testEdgeHoverMode_CYCLE() {

		/*		  
			v1 --> v2 --> v3 --> v4 --> v5 --> v6		  
			       ^      |      ^      |
			       | - <--.      | - <--.
			   
			       cycle 1       cycle 2
		 */

		edge(1, 2);
		edge(2, 3);
		edge(3, 2);
		edge(3, 4);
		edge(4, 5);
		edge(5, 4);
		edge(5, 6);

		hoverMode(PathHighlightMode.CYCLE);

		hoverVertex(v(1));
		assertNoEdgesHovered();

		hoverVertex(v(2));

		//@formatter:off
		assertHovered(edge(2, 3),
					  edge(3, 2));
		//@formatter:on
	}

	@Test
	public void testEdgeHoverMode_PATH() {
		//
		// Test that all paths between the focused and hovered vertices are 'hovered' 
		//

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.PATH);

		focusVertex(v(1));
		hoverVertex(v(2));
		assertHovered(edge(1, 2));

		hoverVertex(v(5));
		//@formatter:off
		assertHovered(edge(1, 2),
					  edge(2, 3),
					  edge(2, 4),
					  edge(3, 5),
					  edge(4, 5));
		//@formatter:on
	}

	@Test
	public void testEdgeHoverMode_SCOPED_FORWARD() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.SCOPED_FORWARD);

		hoverVertex(v(1));
		assertAllEdgesHovered();

		hoverVertex(v(6));
		assertNoEdgesHovered();

		hoverVertex(v(5));
		assertHovered(edge(5, 6));
	}

	@Test
	public void testEdgeHoverMode_SCOPED_REVERSE() {

		/*		  
			   v1
		        |
			   v2
			  / |
		     /  | 
		   v3   v4
		    \   |
		     \  |
		      - v5
		        |
		        |
		        v6		  
		
		 */

		edge(1, 2);
		edge(2, 3);
		edge(2, 4);
		edge(3, 5);
		edge(4, 5);
		edge(5, 6);

		hoverMode(PathHighlightMode.SCOPED_REVERSE);

		hoverVertex(v(1));
		assertNoEdgesHovered();

		hoverVertex(v(6));
		assertAllEdgesHovered();

		hoverVertex(v(2));
		assertHovered(edge(1, 2));
	}

	@Test
	public void testClearEdgeCache() {
		//
		// Test that clearing the cache will keep the circuits already calculated
		//

		/*		  
		v1 --> v2 --> v3 --> v4 --> v5 --> v6		  
		       ^      |      ^      |
		       | - <--.      | - <--.
		   
		       cycle 1       cycle 2
		*/

		edge(1, 2);
		edge(2, 3);
		edge(3, 2);
		edge(3, 4);
		edge(4, 5);
		edge(5, 4);
		edge(5, 6);

		focusMode(PathHighlightMode.ALLCYCLE);

		//@formatter:off
		assertInFocusedPath(edge(2, 3),
			   		   edge(3, 2), 
			   		   edge(4, 5),
			   		   edge(5, 4));
		//@formatter:on

		VisualGraphPathHighlighter<AbstractTestVertex, TestEdge> highlighter =
			graphComponent.getPathHighlighter();
		swing(() -> highlighter.clearEdgeCache());

		//@formatter:off
		assertInFocusedPath(edge(2, 3),
			   		   edge(3, 2), 
			   		   edge(4, 5),
			   		   edge(5, 4));
		//@formatter:on
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	// a shortcut for edge(v(startId), v(endId)), for readability
	private TestEdge edge(int startId, int endId) {
		return edge(v(startId), v(endId));
	}

	/**
	 * Returns the edge for the given vertices, creating it if it does not yet exist.
	 * 
	 * @param v1 the start vertex
	 * @param v2 the end vertex
	 * @return the edge
	 */
	private TestEdge edge(AbstractTestVertex v1, AbstractTestVertex v2) {
		//
		// First, find the exact instance of the edge in the graph, as it may have state 
		// applied to it that we need to verify for testing.
		//
		TestEdge e = graph.findEdge(v1, v2);

		if (graph.containsEdge(e)) {
			return e;
		}

		e = new TestEdge(v1, v2);
		graph.addEdge(e);
		return e;
	}

	// a shortcut for vertex(id), for readability
	private AbstractTestVertex v(int id) {
		return vertex(id);
	}

	/**
	 * Returns the vertex for the given ID, creating it if it does not yet exist.
	 * 
	 * @param id the vertex id
	 * @return the vertex
	 */
	private AbstractTestVertex vertex(int id) {
		//
		// First, find the exact instance of the vertex in the graph, as it may have state 
		// applied to it that we need to verify for testing.
		//
		AbstractTestVertex v = runSwing(() -> {
			LabelTestVertex labelVertex = new LabelTestVertex(Integer.toString(id));
			Collection<AbstractTestVertex> vertices = graph.getVertices();
			for (AbstractTestVertex vertex : vertices) {
				if (labelVertex.equals(vertex)) {
					return vertex;
				}
			}
			return labelVertex;
		});

		graph.addVertex(v);
		return v;
	}

	private void assertInFocusedPath(TestEdge... edges) {
		for (TestEdge e : edges) {
			boolean isFocused = swing(() -> e.isInFocusedVertexPath());
			assertTrue("Edge was not selected: " + e, isFocused);
		}
	}

	private void assertHovered(TestEdge... edges) {

		Set<TestEdge> nonHoveredEdges = new HashSet<>(graph.getEdges());
		Set<TestEdge> expectedEdges = CollectionUtils.asSet(edges);
		nonHoveredEdges.removeAll(expectedEdges);

		for (TestEdge e : expectedEdges) {
			boolean isHovered = swing(() -> e.isInHoveredVertexPath());
			assertTrue("Edge was not hovered: " + e, isHovered);
		}

		for (TestEdge e : nonHoveredEdges) {
			boolean isHovered = swing(() -> e.isInHoveredVertexPath());
			assertFalse("Edge hovered when it should not have been: " + e, isHovered);
		}
	}

	private void assertNotInFocusedPath(TestEdge... edges) {
		for (TestEdge e : edges) {
			boolean isFocused = swing(() -> e.isInFocusedVertexPath());
			assertFalse("Edge should not have been selected: " + e, isFocused);
		}
	}

	private void assertNotHovered(TestEdge... edges) {
		for (TestEdge e : edges) {
			boolean isHovered = swing(() -> e.isInHoveredVertexPath());
			assertFalse("Edge should not have been hovered: " + e, isHovered);
		}
	}

	private void assertNoEdgesInFocusedPath() {
		Collection<TestEdge> edges = graph.getEdges();
		TestEdge[] asArray = edges.toArray(new TestEdge[edges.size()]);
		assertNotInFocusedPath(asArray);
	}

	private void assertNoEdgesHovered() {
		Collection<TestEdge> edges = graph.getEdges();
		TestEdge[] asArray = edges.toArray(new TestEdge[edges.size()]);
		assertNotHovered(asArray);
	}

	private void assertAllEdgesInFocusedPath() {
		Collection<TestEdge> edges = graph.getEdges();
		TestEdge[] asArray = edges.toArray(new TestEdge[edges.size()]);
		assertInFocusedPath(asArray);
	}

	private void assertAllEdgesHovered() {
		Collection<TestEdge> edges = graph.getEdges();
		TestEdge[] asArray = edges.toArray(new TestEdge[edges.size()]);
		assertHovered(asArray);
	}

	private void focusMode(PathHighlightMode mode) {
		swing(() -> graphComponent.setVertexFocusPathHighlightMode(mode));
		waitForPathHighligter();
	}

	private void hoverMode(PathHighlightMode mode) {
		swing(() -> graphComponent.setVertexHoverPathHighlightMode(mode));
		waitForPathHighligter();
	}

	@Override
	protected void focusVertex(AbstractTestVertex v) {
		super.focusVertex(v);
		waitForPathHighligter();
	}

	@Override
	protected void hoverVertex(AbstractTestVertex v) {
		super.hoverVertex(v);
		waitForPathHighligter();
	}

	private void waitForPathHighligter() {
		waitForSwing();
		VisualGraphPathHighlighter<AbstractTestVertex, TestEdge> highlighter =
			graphComponent.getPathHighlighter();
		waitForCondition(() -> !highlighter.isBusy(), "Timed-out waiting for Path Highlighter");
		// waitForAnimation(); don't need to do this, as the edges are hovered while animating
		waitForSwing();
	}

}
