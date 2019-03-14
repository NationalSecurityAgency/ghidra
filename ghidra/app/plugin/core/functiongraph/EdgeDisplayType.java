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
package ghidra.app.plugin.core.functiongraph;

import ghidra.graph.viewer.PathHighlightMode;

/**
 * An enum for mapping the {@link PathHighlightMode} to values for use in UI actions.
 */
public enum EdgeDisplayType {
	PathsToVertex,
	PathsFromVertex,
	PathsFromToVertex,
	Cycles,
	AllCycles,
	PathsFromVertexToVertex,
	ScopedFlowsFromVertex,
	ScopedFlowsToVertex,
	Off;

	public PathHighlightMode getAsPathHighlightHoverMode() {
		switch (this) {
			case PathsToVertex:
				return PathHighlightMode.IN;
			case PathsFromVertex:
				return PathHighlightMode.OUT;
			case PathsFromToVertex:
				return PathHighlightMode.INOUT;
			case Cycles:
				return PathHighlightMode.CYCLE;
			case AllCycles:
				return PathHighlightMode.ALLCYCLE;
			case PathsFromVertexToVertex:
				return PathHighlightMode.PATH;
			case ScopedFlowsFromVertex:
				return PathHighlightMode.SCOPED_FORWARD;
			case ScopedFlowsToVertex:
				return PathHighlightMode.SCOPED_REVERSE;
			case Off:
			default:
				return PathHighlightMode.OFF;
		}
	}
}
