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
package ghidra.examples.graph.layout;

import edu.uci.ics.jung.algorithms.layout.Layout;
import ghidra.examples.graph.*;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class SampleGraphJungLayoutProvider extends SampleGraphLayoutProvider {

	protected abstract Layout<SampleVertex, SampleEdge> createLayout(SampleGraph g);

	@Override
	public VisualGraphLayout<SampleVertex, SampleEdge> getLayout(SampleGraph g, TaskMonitor monitor)
			throws CancelledException {

		Layout<SampleVertex, SampleEdge> jungLayout = createLayout(g);

		initVertexLocations(g, jungLayout);

		return new SampleGraphLayout(jungLayout);
	}

}
