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

import java.awt.geom.Line2D;
import java.awt.geom.Rectangle2D;

import org.junit.Test;

import ghidra.graph.graphs.TestEdge;
import ghidra.graph.graphs.TestVertex;

public class VisualEdgeArrowRenderingSupportTest {

	private double width = 100.0;
	private double height = 100.0;

	private VisualEdgeArrowRenderingSupport<TestVertex, TestEdgeX> arrowSupport =
		new VisualEdgeArrowRenderingSupport<>();

	@Test
	public void testInfiniteLoopOnBisect() {

		// Values are large enough to pass the initial tolerance test, but then precise enough
		// to get stuck in the bisect loop.  Using power of two for values so that our ulp()
		// can be as precise as possible as well.
		double rxf = 8.0f;
		double ryf = 8.0f;

		double rx = rxf + Math.ulp(rxf);
		double ry = ryf + Math.ulp(ryf);

		Rectangle2D vertex = new Rectangle2D.Double(rx, ry, width, height);
		Line2D edge = new Line2D.Double(0.00, 0.00, rx, ry);

		// We don't need the return value for this test
		arrowSupport.findClosestLineSegment(5.0f, edge, vertex);
	}

//==================================================================================================
// Private Class
//==================================================================================================

	class TestEdgeX extends AbstractVisualEdge<TestVertex> {

		public TestEdgeX(TestVertex start, TestVertex end) {
			super(start, end);
		}

		@SuppressWarnings("unchecked")
		// Suppressing warning on the return type; we know our class is the right type
		@Override
		public TestEdge cloneEdge(TestVertex start, TestVertex end) {
			return new TestEdge(start, end);
		}
	}

}
