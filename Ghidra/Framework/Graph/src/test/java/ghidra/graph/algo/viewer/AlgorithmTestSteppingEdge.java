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
package ghidra.graph.algo.viewer;

import ghidra.graph.viewer.edge.AbstractVisualEdge;

public class AlgorithmTestSteppingEdge<V>
		extends AbstractVisualEdge<AlgorithmTestSteppingVertex<V>> {

	AlgorithmTestSteppingEdge(AlgorithmTestSteppingVertex<V> start,
			AlgorithmTestSteppingVertex<V> end) {
		super(start, end);
	}

	// sigh.  I could not get this to compile with 'V' type specified
	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Override
	public AlgorithmTestSteppingEdge<V> cloneEdge(AlgorithmTestSteppingVertex start,
			AlgorithmTestSteppingVertex end) {
		return new AlgorithmTestSteppingEdge<>(start, end);
	}
}
