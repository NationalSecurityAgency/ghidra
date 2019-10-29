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
package ghidra.graph;

import static org.junit.Assert.assertEquals;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;

import javax.swing.JFrame;

import org.junit.Test;

import ghidra.graph.algo.*;
import ghidra.graph.algo.viewer.*;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;

/**
 * A tool, written as a junit, that allows the user to run a test and then use the UI to step
 * through the given graph algorithm.
 */
public class GraphAlgorithmsVisualDebugger extends AbstractGraphAlgorithmsTest {

	@Override
	protected GDirectedGraph<TestV, TestE> createGraph() {
		return GraphFactory.createDirectedGraph();
	}

	@Test
	public void testFindPathsNew_MultiPaths_BackFlows_WithUI_IterativeFindPathsAlgorithm()
			throws CancelledException {

		FindPathsAlgorithm<TestV, TestE> algo = new IterativeFindPathsAlgorithm<>();
		doTestFindPathsNew_MultiPaths_BackFlows_WithUI(algo);
	}

	@Test
	public void testFindPathsNew_MultiPaths_BackFlows_WithUI_RecursiveFindPathsAlgorithm()
			throws CancelledException {

		FindPathsAlgorithm<TestV, TestE> algo = new RecursiveFindPathsAlgorithm<>();
		doTestFindPathsNew_MultiPaths_BackFlows_WithUI(algo);
	}

	private void doTestFindPathsNew_MultiPaths_BackFlows_WithUI(
			FindPathsAlgorithm<TestV, TestE> algo) throws CancelledException {

		/*
		   --> v1		 		
		   |  /  \
		   -v2    v3
			    /  | \
			   v4  v5 v6 <--
			    *  |  |     |
			       |  v7    |
			       |  | \   |
			       |  v8 v9 -
			       |   * 
			       |
			      v10	
			    
			    
			Paths: v1, v3, v5, v10
		*/

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v1); // back edge

		edge(v3, v4);
		edge(v3, v5);
		edge(v3, v6);

		edge(v5, v10);

		edge(v6, v7);

		edge(v7, v8);
		edge(v7, v9);

		edge(v9, v6); // back edge

		AlgorithmSteppingTaskMonitor steppingMonitor = new AlgorithmSteppingTaskMonitor();
		steppingMonitor = new AlgorithmSelfSteppingTaskMonitor(500);
		TestGraphAlgorithmSteppingViewerPanel<TestV, TestE> gp = showViewer(steppingMonitor);

		algo.setStatusListener(gp.getStatusListener());
		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
		algo.findPaths(g, v1, v10, accumulator, steppingMonitor);

		//Msg.debug(this, "Total status updates: " + gp.getStatusListener().getTotalStatusChanges());

		steppingMonitor.pause(); // pause this thread to view the final output

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(1, paths.size());
		assertPathExists(paths, v1, v3, v5, v10);
	}

	private TestGraphAlgorithmSteppingViewerPanel<TestV, TestE> showViewer(
			AlgorithmSteppingTaskMonitor steppingMonitor) {

		String isHeadless = Boolean.toString(false);
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, isHeadless);
		System.setProperty("java.awt.headless", isHeadless);

		JFrame frame = new JFrame("Graph");
		TestGraphAlgorithmSteppingViewerPanel<TestV, TestE> gp =
			new TestGraphAlgorithmSteppingViewerPanel<>(g, steppingMonitor);
		frame.getContentPane().add(gp);
		frame.setSize(800, 800);
		frame.setVisible(true);

		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				steppingMonitor.cancel();
			}
		});

		return gp;
	}
}
