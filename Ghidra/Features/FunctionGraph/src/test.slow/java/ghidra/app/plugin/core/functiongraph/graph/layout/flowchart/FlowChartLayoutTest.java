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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import org.junit.Before;
import org.junit.Test;

import ghidra.graph.graphs.LabelTestVertex;
import ghidra.graph.support.TestVisualGraph;
import ghidra.util.exception.CancelledException;

public class FlowChartLayoutTest extends AbstractFlowChartLayoutTest {

	public FlowChartLayoutTest() {
		super(false);
	}

	@Override
	@Before
	public void setUp() {
		g = new TestVisualGraph();
	}

	@Test
	public void testBasicRootWithTwoChildren() throws CancelledException {

		edge(A, B);
		edge(A, C);
		showGraph();

		assertVertices("""
				....
				..A.
				....
				.B.C
				""");

		assertEdge(e(A, B)
				.colSegment(down(1), offset(-1))
				.rowSegment(left(1), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(1), offset(1))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(0)));

	}

	@Test
	public void testBasicGraphWithThreeChildren() throws CancelledException {
		edge(A, B);
		edge(A, C);
		edge(A, D);
		applyLayout();

		showGraph();

		assertVertices("""
				......
				...A..
				......
				.B.C.D
				""");

		assertEdge(e(A, B)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, D)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(0)));

	}

	@Test
	public void testBasicGraphWithBackEdge() throws CancelledException {
		edge(A, B);
		edge(A, C);
		edge(A, D);
		edge(D, A);
		applyLayout();

//		showGraph();

		assertVertices("""
				.......
				...A...
				.......
				.B.C.D.
				.......
				""");

		assertEdge(e(A, B)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, D)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(D, A)
				.colSegment(down(1), offset(0))
				.rowSegment(right(1), offset(0))
				.colSegment(up(4), offset(0))
				.rowSegment(left(3), offset(0))
				.colSegment(down(1), offset(0)));

	}

	@Test
	public void testComplexGraph() throws CancelledException {

		//@formatter:off
		/*
				  A
			 	  |
				  B
			 	  |
	sink    C <---D
		    |	  |
		   	|	  E
			| 	//   \
			|  |F    G
		    |  ||\   |
		    |  |H | /
		    |  | \|/ 
		    |  |  I
			|  | / \
		    |  |/   \
		    .<-K---->J	sink

		*/
		//@formatter:on		edge(A, B);
		edge(A, B);
		edge(B, D);
		edge(D, C);
		edge(D, E);

		edge(E, F);
		edge(E, G);
		edge(E, K);
		edge(F, H);
		edge(F, I);
		edge(G, I);
		edge(H, I);
		edge(I, J);
		edge(I, K);
		edge(K, C);
		edge(K, J);

		applyLayout();

//		showGraph();

		assertVertices("""
				.....
				...A.
				.....
				...B.
				.....
				...D.
				.....
				...E.
				.....
				..F.G
				.....
				..H..
				.....
				..I..
				.....
				..K..
				.....
				.C.J.
				""");

		assertEdge(e(A, B)
				.colSegment(down(2), offset(0)));

		assertEdge(e(B, D)
				.colSegment(down(2), offset(0)));

		assertEdge(e(D, C)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(2), offset(0))
				.colSegment(down(11), offset(-1)));

		assertEdge(e(D, E)
				.colSegment(down(2), offset(0)));

		assertEdge(e(E, F)
				.colSegment(down(1), offset(-1))
				.rowSegment(left(1), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(E, G)
				.colSegment(down(1), offset(3))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(E, K)
				.colSegment(down(7), offset(1))
				.rowSegment(left(1), offset(2))
				.colSegment(down(1), offset(2)));

		assertEdge(e(F, H)
				.colSegment(down(2), offset(0)));

		assertEdge(e(F, I)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(1), offset(0))
				.colSegment(down(2), offset(1))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(-2)));

		assertEdge(e(G, I)
				.colSegment(down(3), offset(0))
				.rowSegment(left(2), offset(0))
				.colSegment(down(1), offset(2)));

		assertEdge(e(H, I)
				.colSegment(down(2), offset(0)));

		assertEdge(e(I, J)
				.colSegment(down(1), offset(2))
				.rowSegment(right(1), offset(0))
				.colSegment(down(3), offset(-1)));
		assertEdge(e(I, K)
				.colSegment(down(2), offset(0)));

		assertEdge(e(K, C)
				.colSegment(down(1), offset(-1))
				.rowSegment(left(1), offset(0))
				.colSegment(down(1), offset(1)));

		assertEdge(e(K, J)
				.colSegment(down(1), offset(1))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(-3)));
	}

	@Test
	public void testGraphThatBenefitsFromComparingEdgesUsingFlow() throws CancelledException {
		LabelTestVertex X = v('X');
		LabelTestVertex Y = v('Y');
		LabelTestVertex Z = v('Z');
		LabelTestVertex W = v('W');

		edge(A, B);
		edge(A, C);
		edge(A, D);
		edge(B, K);
		edge(K, J);
		edge(D, F);
		edge(G, I);
		edge(D, E);
		edge(E, G);
		edge(F, Z);
		edge(F, H);
		edge(E, I);
		edge(J, W);
		edge(W, X);
		edge(W, Y);
		edge(W, Z);

		applyLayout();

//		showGraph();

		assertVertices("""
				.........
				.....A...
				.........
				...B.C.D.
				.........
				...K..E.F
				.........
				...J..G.H
				.........
				...W..I..
				.........
				.X.Y.Z...
				""");

		assertEdge(e(A, B)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, D)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(B, K)
				.colSegment(down(2), offset(0)));

		assertEdge(e(K, J)
				.colSegment(down(2), offset(0)));

		assertEdge(e(J, W)
				.colSegment(down(2), offset(0)));

		assertEdge(e(W, X)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(W, Y)
				.colSegment(down(2), offset(0)));

		assertEdge(e(W, Z)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(-1)));

		assertEdge(e(D, E)
				.colSegment(down(1), offset(-1))
				.rowSegment(left(1), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(D, F)
				.colSegment(down(1), offset(1))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(E, I)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(1), offset(0))
				.colSegment(down(2), offset(-1))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(-2)));

		assertEdge(e(E, G)
				.colSegment(down(2), offset(0)));

		assertEdge(e(F, H)
				.colSegment(down(2), offset(0)));

		assertEdge(e(F, Z)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(3), offset(2))
				.colSegment(down(5), offset(1)));

	}

}
