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
package functioncalls.graph.job;

import java.util.Set;

import functioncalls.graph.FcgEdge;
import functioncalls.graph.FcgVertex;
import ghidra.graph.job.AbstractGraphVisibilityTransitionJob;
import ghidra.graph.viewer.GraphViewer;

/**
 * A job to emphasize a given set of edges.  This will make them bigger and then restore them 
 * to a non-emphasized state.
 */
public class FcgEmphasizeEdgesJob extends AbstractGraphVisibilityTransitionJob<FcgVertex, FcgEdge> {

	private Set<FcgEdge> edges;

	public FcgEmphasizeEdgesJob(GraphViewer<FcgVertex, FcgEdge> viewer, Set<FcgEdge> edges) {
		super(viewer, true);
		this.edges = edges;
	}

	@Override
	protected void updateOpacity(double percentComplete) {

		double remaining = percentComplete;
		if (percentComplete > .5) {
			remaining = 1 - percentComplete;
		}

		double modified = remaining * 10;

		//double remaining = 1 - percentComplete;  // start opacity towards the end
		for (FcgEdge e : edges) {
			e.setEmphasis(modified);
		}
	}
}
