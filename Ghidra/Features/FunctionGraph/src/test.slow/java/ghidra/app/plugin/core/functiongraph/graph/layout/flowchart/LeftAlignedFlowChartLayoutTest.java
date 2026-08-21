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

import org.junit.Test;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class LeftAlignedFlowChartLayoutTest extends AbstractFlowChartLayoutTest {

	public LeftAlignedFlowChartLayoutTest() {
		super(true);
	}

	@Test
	public void testBasicRootWithTwoChildren() throws CancelledException {
		edge(A, B);
		edge(A, C);
		applyLayout();

//		showGraph();
//		Msg.out(grid.toStringGrid());

		assertVertices("""
				....
				.A..
				....
				.B.C
				""");

		assertEdge(e(A, B)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(0)));

	}

	@Test
	public void testBasicGraphWithThreeChildren() throws CancelledException {
		edge(A, B);
		edge(A, C);
		edge(A, D);
		applyLayout();

//		showGraph();
		Msg.out(grid.toStringGrid());

		assertVertices("""
				......
				.A....
				......
				.B.C.D
				""");

		assertEdge(e(A, B)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(2))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, D)
				.colSegment(down(1), offset(4))
				.rowSegment(right(4), offset(0))
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
//		Msg.out(grid.toStringGrid());

		assertVertices("""
				.......
				.A.....
				.......
				.B.C.D.
				.......
				""");

		assertEdge(e(A, B)
				.colSegment(down(2), offset(0)));

		assertEdge(e(A, C)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(2))
				.colSegment(down(1), offset(0)));

		assertEdge(e(A, D)
				.colSegment(down(1), offset(4))
				.rowSegment(right(4), offset(0))
				.colSegment(down(1), offset(0)));
		assertEdge(e(D, A)
				.colSegment(down(1), offset(0))
				.rowSegment(right(1), offset(0))
				.colSegment(up(4), offset(0))
				.rowSegment(left(5), offset(0))
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

		showGraph();
		Msg.out(grid.toStringGrid());

		assertVertices("""
				....
				.A..
				....
				.B..
				....
				.D..
				....
				.E..
				....
				.F.G
				....
				.H..
				....
				.I..
				....
				.K..
				....
				.C.J
				""");

		assertEdge(e(A, B)
				.colSegment(down(2), offset(0)));

		assertEdge(e(B, D)
				.colSegment(down(2), offset(0)));

		assertEdge(e(D, C)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(1), offset(0))
				.colSegment(down(10), offset(-2))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(-2)));

		assertEdge(e(D, E)
				.colSegment(down(2), offset(0)));

		assertEdge(e(E, F)
				.colSegment(down(2), offset(0)));

		assertEdge(e(E, G)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(0)));

		assertEdge(e(E, K)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(1), offset(0))
				.colSegment(down(6), offset(0))
				.rowSegment(right(1), offset(0))
				.colSegment(down(1), offset(-2)));

		assertEdge(e(F, H)
				.colSegment(down(2), offset(0)));

		assertEdge(e(F, I)
				.colSegment(down(1), offset(-2))
				.rowSegment(left(1), offset(0))
				.colSegment(down(2), offset(2))
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
				.rowSegment(right(2), offset(0))
				.colSegment(down(3), offset(1)));
		assertEdge(e(I, K)
				.colSegment(down(2), offset(0)));

		assertEdge(e(K, C)
				.colSegment(down(2), offset(0)));

		assertEdge(e(K, J)
				.colSegment(down(1), offset(2))
				.rowSegment(right(2), offset(0))
				.colSegment(down(1), offset(-1)));
	}

}
