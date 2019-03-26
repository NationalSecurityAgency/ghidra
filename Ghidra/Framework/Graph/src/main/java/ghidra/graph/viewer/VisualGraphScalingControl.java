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
package ghidra.graph.viewer;

import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.Layer;
import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.control.ScalingControl;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;

/**
 * An implementation of {@link ScalingControl} that allows us to zoom in and out of the view.
 */
public class VisualGraphScalingControl implements ScalingControl {

	private double crossover = 1.0; // full size

	@Override
	public void scale(VisualizationServer<?, ?> vv, float amount, Point2D at) {
		MutableTransformer layoutTransformer =
			vv.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.LAYOUT);
		MutableTransformer viewTransformer =
			vv.getRenderContext().getMultiLayerTransformer().getTransformer(Layer.VIEW);
		double modelScale = layoutTransformer.getScale();
		double viewScale = viewTransformer.getScale();
		double inverseViewScale = Math.sqrt(crossover) / viewScale;
		double scale = modelScale * viewScale;

		//
		// Use the 'at' value unless the options dictate otherwise
		//
		if (!useMouseRelativeZoom(vv)) {
			at = vv.getCenter();
		}

		if (scale * amount < crossover) {
			// scale the viewTransformer, return the layoutTransformer to crossover value
			viewTransformer.scale(amount, amount, at);
		}
		// just restore the scale, but don't adjust the layout
		else {
			viewTransformer.scale(inverseViewScale, inverseViewScale, at);
		}
		vv.repaint();
	}

	private boolean useMouseRelativeZoom(VisualizationServer<?, ?> vv) {

		if (!(vv instanceof GraphViewer)) {
			return true;
		}
		GraphViewer<?, ?> graphViewer = (GraphViewer<?, ?>) vv;
		return graphViewer.useMouseRelativeZoom();
	}
}
