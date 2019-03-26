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
package ghidra.graph.job;

import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.VisualizationServer;
import ghidra.graph.viewer.GraphViewerUtils;

public class MoveViewToViewSpacePointAnimatorFunctionGraphJob<V, E>
		extends MoveViewAnimatorFunctionGraphJob<V, E> {

	private Point2D viewSpacePoint;

	public MoveViewToViewSpacePointAnimatorFunctionGraphJob(VisualizationServer<V, E> viewer,
			Point2D viewSpacePoint, boolean useAnimation) {
		super(viewer, useAnimation);
		this.viewSpacePoint = viewSpacePoint;
	}

	@Override
	protected Point2D createDestination() {
		return GraphViewerUtils.getOffsetFromCenterForPointInViewSpace(viewer, viewSpacePoint);
	}
}
