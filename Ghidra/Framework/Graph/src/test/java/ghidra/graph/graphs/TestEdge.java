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
package ghidra.graph.graphs;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

/**
 * An edge for testing.
 */
public class TestEdge extends AbstractVisualEdge<AbstractTestVertex> {

	public TestEdge(AbstractTestVertex start, AbstractTestVertex end) {
		super(start, end);
	}

	@SuppressWarnings("unchecked")
	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public TestEdge cloneEdge(AbstractTestVertex start, AbstractTestVertex end) {
		return new TestEdge(start, end);
	}
}
