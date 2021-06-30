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

import java.util.Set;

import ghidra.util.graph.AbstractDependencyGraph;
import ghidra.util.task.TaskMonitor;

public class ConcurrentGraphQ<I> {
	private ConcurrentQ<I, Object> queue;
	private AbstractDependencyGraph<I> graph;

	public ConcurrentGraphQ(QRunnable<I> runnable, AbstractDependencyGraph<I> graph,
			GThreadPool pool, TaskMonitor monitor) {
		this.graph = graph;
		// @formatter:off
		queue = new ConcurrentQBuilder<I, Object>()
			.setCollectResults(false)
			.setThreadPool(pool)
			.setMonitor(monitor)
			.setListener(new MyItemListener())
			.build(new QRunnableAdapter<>(runnable));
		// @formatter:on

	}

	public void execute() throws InterruptedException, Exception {

		Set<I> values = graph.getUnvisitedIndependentValues();
		queue.add(values);
		queue.waitUntilDone();
	}

	public void dispose() {
		queue.dispose();
	}

	class MyItemListener implements QItemListener<I, Object> {

		@Override
		public void itemProcessed(QResult<I, Object> result) {
			graph.remove(result.getItem());
			Set<I> values = graph.getUnvisitedIndependentValues();
			queue.add(values);
		}
	}

}
