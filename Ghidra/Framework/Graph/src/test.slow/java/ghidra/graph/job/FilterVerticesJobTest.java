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
package ghidra.graph.job;

import static org.junit.Assert.assertEquals;

import java.awt.Dimension;
import java.util.Set;
import java.util.function.Predicate;

import javax.swing.JFrame;

import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;

import edu.uci.ics.jung.algorithms.layout.DAGLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import generic.test.AbstractGenericTest;
import ghidra.graph.graphs.*;
import ghidra.graph.support.TestGraphLayout;
import ghidra.graph.support.TestGraphViewer;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.SystemUtilities;
import util.CollectionUtils;

public class FilterVerticesJobTest extends AbstractFilteringVisualGraphTest {

	private GraphJobRunner jobRunner = new GraphJobRunner();
	private int jobCount;

	private TestGraphViewer viewer;

	// our animals
	private AbstractTestVertex cat;
	private AbstractTestVertex bat;
	private AbstractTestVertex fish;
	private AbstractTestVertex bee;
	private AbstractTestVertex antelope;
	private AbstractTestVertex worm;
	private AbstractTestVertex ape;
	private AbstractTestVertex turtle;

	@Before
	public void setUp() {

		// some of the underlying graph code (like the Job Runner) need to be in headed mode
		// to work properly
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");

		graph = new FilteringVisualGraph<AbstractTestVertex, TestEdge>() {

			@Override
			public VisualGraphLayout<AbstractTestVertex, TestEdge> getLayout() {
				// we don't need these for this test
				return null;
			}

			@Override
			public DefaultVisualGraph<AbstractTestVertex, TestEdge> copy() {
				// we don't need these for this test
				return null;
			}
		};

		/*		 
							cat
		 					/|\
		 				   / | \
		 				 bat |  fish---->bee
		 				     |
		 				  antelope
		 				  
		 		    worm     ape------>turtle
		
		 */

		cat = vertex("cat");
		bat = vertex("bat");
		fish = vertex("fish");
		bee = vertex("bee");
		antelope = vertex("antelope");
		worm = vertex("worm");
		ape = vertex("ape");
		turtle = vertex("turtle");
		edge(cat, bat);
		edge(cat, fish);
		edge(fish, bee);
		edge(cat, antelope);
		edge(ape, turtle);

		Layout<AbstractTestVertex, TestEdge> jungLayout = new DAGLayout<>(graph);
		TestGraphLayout testLayout = new TestGraphLayout(jungLayout);
		viewer = new TestGraphViewer(testLayout, new Dimension(400, 400));

		JFrame frame = new JFrame("Graph Viewer Test");
		frame.setSize(400, 400);
		frame.getContentPane().add(viewer);
		frame.setVisible(true);

		// enable tracing for debugging
		//LoggingInitialization.initializeLoggingSystem();
		//Logger logger = LogManager.getLogger(GraphJobRunner.class);
		//Configurator.setLevel(logger.getName(), Level.TRACE);
	}

	@Test
	public void testFilter_Remove_NonMatchingButConnectedVertices() {

		boolean remove = true;
		filter("a", remove);

		/*
		 	Matching 'a':
		 		-cat, bat, antelope, ape
		 	Not Matching:
		 		-fish, worm, turtle, bee
		 		
		 	Matches by Connection:
		 		-cat-->fish-->bee
		 		-ape-->turtle
		 	
		 	And excluded will be:
		 		-worm (poor worm)
		 		
		 */

		assertOnlyTheseAreFiltered(worm);
		assertAllVisibleBut(worm);
		assertNoEdgesFiltered();
		assertAllEdgesVisible();

		unfilter();

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
		assertAllVerticesVisible();
		assertAllEdgesVisible();
	}

	@Test
	public void testMultipleConsecutiveFilters() {
		boolean remove = true;
		filter("a", remove);

		filter("at", remove);

		/*
		  	Matching 'at':
		 		-cat, bat, antelope
		 	Not Matching:
		 		-fish, worm, ape, turtle, bee
		 		
		 	Matches by Connection:
		 		-cat-->fish-->bee
		 		
		 	And excluded will be:
		 		-worm, ape, turtle
		 		-ape-->turtle
		 */

		AbstractTestVertex[] failed = new AbstractTestVertex[] { worm, ape, turtle };
		assertOnlyTheseAreFiltered(failed);
		assertAllVisibleBut(failed);
		TestEdge apeToTurtle = edge(ape, turtle);
		assertOnlyTheseAreFiltered(apeToTurtle);
		assertAllVisibleBut(apeToTurtle);

		unfilter();

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
		assertAllVerticesVisible();
		assertAllEdgesVisible();
	}

	@Test
	public void testMultipleFilters_Remove_ShortcutEachFilter() {

		filterSlowly("zed", true); // no matches
		filterSlowly("cow", true); // no matches
		filterSlowly("at", true);
		shortCutAllJobs(); // let's not wait forever

		/*
		  	Matching 'at':
		 		-cat, bat, antelope
		 		
		 	Not Matching:
		 		-fish, worm, ape, turtle, bee
		 				 				 		
		 	Matches by Connection:
		 		-cat-->fish-->bee
		 	
		 	And excluded will be:
		 		-worm, ape, turtle
		 		-ape-->turtle
		*/

		waitForJobRunner();

		AbstractTestVertex[] filteredOut = new AbstractTestVertex[] { worm, ape, turtle };
		assertOnlyTheseAreFiltered(filteredOut);
		assertAllVisibleBut(filteredOut);
		TestEdge apeToTurtle = edge(ape, turtle);
		assertOnlyTheseAreFiltered(apeToTurtle);
		assertAllVisibleBut(apeToTurtle);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	/** Validate the alpha of the graph vertices */
	private void assertAllVisibleBut(AbstractTestVertex... vertices) {

		Set<AbstractTestVertex> visible = getAllVertices();
		Set<AbstractTestVertex> hidden = CollectionUtils.asSet(vertices);

		visible.removeAll(hidden);

		hidden.forEach(v -> assertAlphaEquals(0, v.getAlpha()));
		visible.forEach(v -> assertAlphaEquals(1, v.getAlpha()));
	}

	/** Validate the alpha of the graph edges */
	private void assertAllVisibleBut(TestEdge... edges) {

		Set<TestEdge> visible = getAllEdges();
		Set<TestEdge> hidden = CollectionUtils.asSet(edges);

		visible.removeAll(hidden);

		hidden.forEach(e -> assertAlphaEquals(0, e.getAlpha()));
		visible.forEach(e -> assertAlphaEquals(1, e.getAlpha()));
	}

	private void assertAllEdgesVisible() {
		Set<TestEdge> edges = getAllEdges();
		edges.forEach(e -> assertAlphaEquals(1, e.getAlpha()));
	}

	private void assertAllVerticesVisible() {
		Set<AbstractTestVertex> vertices = getAllVertices();
		vertices.forEach(v -> assertAlphaEquals(1, v.getAlpha()));
	}

	private void assertAlphaEquals(double expected, double actual) {
		double delta = .0001; // not sure what the margin of error is
		assertEquals(expected, actual, delta);
	}

	private void filter(String filterText, boolean remove) {
		filter(filterText, remove, 100 /* speed-up for testing */);
	}

	private void filter(String filterText, boolean remove, int filterDuration) {
		Predicate<AbstractTestVertex> filter = v -> StringUtils.containsIgnoreCase(v.getName(), filterText);
		FilterVerticesJob<AbstractTestVertex, TestEdge> job =
			new FilterVerticesJob<>(viewer, graph, filter, remove);
		job.duration = filterDuration;
		jobRunner.schedule(job);
		waitForJobRunner();
	}

	private void filterSlowly(String filterText, boolean remove) {
		Predicate<AbstractTestVertex> filter = v -> StringUtils.containsIgnoreCase(v.getName(), filterText);
		FilterVerticesJob<AbstractTestVertex, TestEdge> job =
			new FilterVerticesJob<AbstractTestVertex, TestEdge>(viewer, graph, filter, remove) {

				private int myId = ++jobCount;

				@Override
				public String toString() {
					return "Filter Job " + myId;
				}
			};
		job.duration = 10000;
		jobRunner.schedule(job);

		// Do not wait--we use this to allow for job interruption
		// waitForJobRunner();
	}

	private void shortCutAllJobs() {
		jobRunner.finishAllJobs();
	}

	private void unfilter() {
		filter("", false);
	}

	private void waitForJobRunner() {
		AbstractGenericTest.waitForCondition(() -> !jobRunner.isBusy(),
			"Filter job never finished");
	}
}
