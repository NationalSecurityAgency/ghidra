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
package ghidra.service.graph;

import java.util.Set;

public class DummyGraphDisplayListener implements GraphDisplayListener {

	@Override
	public void graphClosed() {
		// I'm a dummy
	}

	@Override
	public GraphDisplayListener cloneWith(GraphDisplay graphDisplay) {
		return new DummyGraphDisplayListener();
	}

	@Override
	public void selectionChanged(Set<AttributedVertex> vertices) {
		// I'm a dummy
	}

	@Override
	public void locationFocusChanged(AttributedVertex vertex) {
		// I'm a dummy
	}

	@Override
	public void dispose() {
		// I'm a dummy
	}

}
