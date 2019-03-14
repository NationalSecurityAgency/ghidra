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
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.JungWrappingVisualGraphLayoutAdapter;

/**
 * A {@link SampleGraphPlugin} layout that can be used to apply existing Jung layouts.
 */
public class SampleGraphJungLayout
		extends JungWrappingVisualGraphLayoutAdapter<SampleVertex, SampleEdge> {

	public SampleGraphJungLayout(Layout<SampleVertex, SampleEdge> jungLayout) {
		super(jungLayout);
	}

	@Override
	protected Layout<SampleVertex, SampleEdge> cloneJungLayout(
			VisualGraph<SampleVertex, SampleEdge> newGraph) {

		Layout<SampleVertex, SampleEdge> newJungLayout = cloneJungLayout(newGraph);
		return new SampleGraphJungLayout(newJungLayout);
	}

	Layout<?, ?> getJungLayout() {
		return delegate;
	}
}
