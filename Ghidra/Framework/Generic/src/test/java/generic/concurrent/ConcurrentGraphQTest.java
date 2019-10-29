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
package generic.concurrent;

import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.graph.DependencyGraph;
import ghidra.util.task.TaskMonitor;

public class ConcurrentGraphQTest extends AbstractGenericTest {

	public ConcurrentGraphQTest() {
		super();
	}

	@Test
	public void test() throws InterruptedException, Exception {
		final ArrayList<String> completionOrder = new ArrayList<>();

		AbstractDependencyGraph<String> graph = new DependencyGraph<>();
		graph.addDependency("@0", "A8");
		graph.addDependency("@1", "A1");
		graph.addDependency("@2", "A7");
		graph.addDependency("@3", "A2");
		graph.addDependency("@4", "A3");
		graph.addDependency("@5", "A3");
		graph.addDependency("@6", "A4");
		graph.addDependency("@7", "A4");
		graph.addDependency("@A", "A5");
		graph.addDependency("@B", "A5");
		graph.addDependency("@C", "A6");
		graph.addDependency("@D", "A6");
		graph.addDependency("@E", "A7");
		graph.addDependency("@F", "A2");
		graph.addDependency("@G", "A8");
		graph.addDependency("@H", "A1");

		graph.addDependency("A1", "B4");
		graph.addDependency("A2", "B1");
		graph.addDependency("A3", "B2");
		graph.addDependency("A4", "B2");
		graph.addDependency("A5", "B3");
		graph.addDependency("A6", "B3");
		graph.addDependency("A7", "B4");
		graph.addDependency("A8", "B1");
		graph.addDependency("B1", "C2");
		graph.addDependency("B2", "C1");
		graph.addDependency("B3", "C2");
		graph.addDependency("B4", "C1");
		graph.addDependency("C1", "D1");
		graph.addDependency("C2", "D1");

		assertTrue(!graph.hasCycles());

		AbstractDependencyGraph<String> savedGraph = graph.copy();

		GThreadPool pool = GThreadPool.getPrivateThreadPool("ConcurrentGraphQ Test");
		QRunnable<String> runnable = new QRunnable<>() {

			@Override
			public void run(String item, TaskMonitor monitor) throws Exception {
//				System.out.println("Processing item " + item + " in thread" +
//					Thread.currentThread().getName());
//				sleep(1000);
				synchronized (completionOrder) {
					completionOrder.add(item);
				}
			}
		};

		ConcurrentGraphQ<String> queue = new ConcurrentGraphQ<>(runnable, graph, pool, null);
		queue.execute();
		checkOrderSatisfiesDependencies(savedGraph, completionOrder);
	}

	/**
	 * Given a dependency map, does the captured linear order of execution 
	 * satisfy the ordering constraints?
	 * @param <T> the type of the keys being compared
	 * @param dependencyGraph a map where keys are predecessors and values 
	 *        are successors that depend on the respective key
	 * @param visitedOrder the actual execution order to be tested
	 * @return
	 */
	public void checkOrderSatisfiesDependencies(AbstractDependencyGraph<String> dependencyGraph,
			List<String> visitedOrder) {

		if (visitedOrder.size() > dependencyGraph.size()) {
			Assert.fail("More items were visited than the number of items in the graph");
		}
		if (visitedOrder.size() < dependencyGraph.size()) {
			Assert.fail("Not all items in the graph were visited");
		}

		HashSet<String> items = new HashSet<>(visitedOrder);
		if (items.size() != visitedOrder.size()) {
			Assert.fail("duplicate item(s) in linearOrder\n");
		}

		HashMap<String, Integer> visitedOrderMap = new HashMap<>();
		for (int i = 0; i < visitedOrder.size(); i++) {
			visitedOrderMap.put(visitedOrder.get(i), i);
		}

		for (String key : dependencyGraph.getValues()) {
			Integer visitedOrdinal = visitedOrderMap.get(key);
			if (visitedOrdinal == null) {
				Assert.fail("dependencyGraph key " + key + " not in linearOrder\n");
			}

			Set<String> dependents = dependencyGraph.getDependentValues(key);
			for (String dependent : dependents) {
				if (key.equals(dependent)) {
					Assert.fail("dependencyGraph key " + key + " depends on itself\n");
				}
				Integer dependentVisitedOrdinal = visitedOrderMap.get(dependent);
				if (dependentVisitedOrdinal == null) {
					Assert.fail("dependent " + dependent + " of dependencyGraph key " + key +
						" not in linearOrder\n");
				}
				if (dependentVisitedOrdinal <= visitedOrdinal) {
					Assert.fail("dependent " + dependent + " of dependencyGraph key " + key +
						" came first (" + dependentVisitedOrdinal + " < " + visitedOrdinal + ")\n");
				}
			}
		}
	}

}
