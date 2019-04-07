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
package ghidra.graph.viewer.renderer;

import java.awt.*;
import java.awt.geom.AffineTransform;

import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.VisualizationServer.Paintable;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.GraphViewer;
import ghidra.util.datastruct.FixedSizeStack;

public class MouseDebugPaintable implements Paintable {

	// the size can be bigger if needed
	private FixedSizeStack<PaintableShape> shapes = new FixedSizeStack<>(30);
	private GraphViewer<?, ?> viewer;

	@Override
	public boolean useTransform() {
		return true;
	}

	@Override
	public void paint(Graphics g) {

		if (shapes.isEmpty()) {
			return;
		}

		Graphics2D g2d = (Graphics2D) g;
		AffineTransform oldXform = g2d.getTransform();

		RenderContext<?, ?> rc = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		MutableTransformer layoutXformer = multiLayerTransformer.getTransformer(Layer.LAYOUT);
		AffineTransform layoutXform = layoutXformer.getTransform();

		double tx = layoutXform.getTranslateX();
		double ty = layoutXform.getTranslateY();

		for (PaintableShape s : shapes) {

			if (s.isShapeFinished()) {
				// this will draw the shape, after dragging is finished, at a position
				// relative to its start point 
				double dx = tx - s.getTx();
				double dy = ty - s.getTy();

				AffineTransform newXform = new AffineTransform(oldXform);
				newXform.translate(dx, dy);
				g2d.setTransform(newXform);
			}

			Stroke oldStroke = g2d.getStroke();
			Color oldColor = g2d.getColor();

			s.paint(g2d);

			g2d.setStroke(oldStroke);
			g2d.setColor(oldColor);
			g2d.setTransform(oldXform);
		}
	}

	public void addShape(PaintableShape shape, GraphViewer<?, ?> graphViewer) {
		this.viewer = graphViewer;
		shapes.add(shape);
	}

	public void clear() {
		shapes.clear();
	}
}
