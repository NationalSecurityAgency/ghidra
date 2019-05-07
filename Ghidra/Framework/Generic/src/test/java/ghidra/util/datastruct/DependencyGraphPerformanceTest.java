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
package ghidra.util.datastruct;

import java.util.*;

import ghidra.util.graph.DependencyGraph;
import ghidra.util.graph.DeterministicDependencyGraph;

/**
 * Performs computation of dependency graph
 * Does not test the accuracy/functionality of Dependency Graphs.
 */
public class DependencyGraphPerformanceTest {

	// Specifying the graph edge density ratio: number of edges over the
	//  number of possible edges (|E|/P(|V|,2). 
	//  For sparse graphs, where |E|=O(n), can do |E|/|V|.
	//  TODO: What is good for testing.
	private static final long GRAPH_SEED = 12345L;
	private static final double GRAPH_EDGE_DENSITY = 0.20;
	private static final int NUM_DEPENDENCIES = 30000;
	private static final int GRAPH_SIZE = (int) (NUM_DEPENDENCIES / GRAPH_EDGE_DENSITY);
	private static final boolean GRAPH_ALLOW_CYCLES = false;

	private final List<DependencyRelation> testRelationships;

	public DependencyGraphPerformanceTest() {
		testRelationships = constructRandomRelationships(GRAPH_SEED, NUM_DEPENDENCIES, GRAPH_SIZE,
			GRAPH_ALLOW_CYCLES);
	}

	// Not intended for nightly or continuous testing. Comment in when needed during development.
//	@Test
	public void testLargeDependencyGraph() {
		Timer timer = new Timer("DependencyGraph");
		timer.mark();
		DependencyGraph<String> graph = new DependencyGraph<>();
		for (DependencyRelation relation : testRelationships) {
			graph.addDependency(relation.dependent, relation.dependee);
		}
		timer.mark();
		while (!graph.isEmpty()) {
			graph.pop();
		}
		timer.mark();
		System.out.println(timer);
	}

	// Not intended for nightly or continuous testing. Comment in when needed during development.
//	@Test
	public void testLargeDeterministicDependencyGraph() {
		Timer timer = new Timer("DeterministicDependencyGraph");
		timer.mark();
		DeterministicDependencyGraph<String> graph = new DeterministicDependencyGraph<>();
		for (DependencyRelation relation : testRelationships) {
			graph.addDependency(relation.dependent, relation.dependee);
		}
		timer.mark();
		while (!graph.isEmpty()) {
			graph.pop();
		}
		timer.mark();
		System.out.println(timer);
	}

	private class Timer {
		private String testName;
		private List<Long> times = new ArrayList<>();

		public Timer(String testName) {
			this.testName = testName;
		}

		public void mark() {
			times.add(System.currentTimeMillis());
		}

		@Override
		public String toString() {
			String report = testName + " (milliseconds)\n";
			if (!times.isEmpty()) {
				long prev = times.get(0);
				long total = times.get(times.size() - 1) - prev;
				for (int i = 1; i < times.size(); i++) {
					long current = times.get(i);
					long diff = current - prev;
					report += String.format("  %03d: %d\n", i, diff);
					prev = current;
				}
				report += String.format("total: %d\n", total);
			}
			return report;
		}
	}

	private class DependencyRelation {
		public String dependent;
		public String dependee;

		public DependencyRelation(int dependentId, int dependeeId) {
			dependent = "V" + dependentId;
			dependee = "V" + dependeeId;
		}
	}

	private List<DependencyRelation> constructRandomRelationships(long seed, int numDependencies,
			int graphSize, boolean allowCycles) {
		List<DependencyRelation> relationships = new ArrayList<>();
		Random generator = new Random(seed);

		// Not taking a dependent beyond 90% of graph size; similar dependee only in latter
		// 90%.
		double factor = 0.90;
		int limit = (int) (factor * graphSize);
		int dependeeOffset = graphSize - limit;
		assert limit != graphSize;

		// TODO: currently ignoring allowCycles parameter.
		// TODO: Do no cycles for now... ask if would need both types for performance testing.
		// To disallow cycles, we simply are preventing the dependee number from being less than
		//  the dependent number.  This weights the graph in an interesting way: dependents with
		//  smaller numbers will tend to have more dependees.
		for (int i = 0; i < numDependencies; i++) {
			int dependentId = generator.nextInt(limit);
			int dependeeId;
			do {
				dependeeId = generator.nextInt(limit) + dependeeOffset;
			}
			while (dependeeId <= dependentId);
			DependencyRelation relation = new DependencyRelation(dependentId, dependeeId);
			relationships.add(relation);
		}
		return relationships;
	}

}
