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
import java.awt.geom.Rectangle2D;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.SwingUtilities;

import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.VisualizationServer.Paintable;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;

public class DebugShape<V, E> implements Paintable {

	private Shape shape;
	private Color color;
	private String text;

	private VisualizationServer<V, E> viewer;
	private AtomicInteger drawingIterationCounter;
	private final int drawingIterationID;

	public DebugShape(VisualizationServer<V, E> viewer, AtomicInteger drawingIterationCounter,
			String text, Shape shape, Color color) {
		this.viewer = viewer;
		this.drawingIterationCounter = drawingIterationCounter;
		this.text = text == null ? "no text" : text;
		this.shape = shape;
		this.color = color;
		this.drawingIterationID = drawingIterationCounter.get();
	}

	public Shape getShape() {
		return shape;
	}

	public Color getColor() {
		return color;
	}

	@Override
	public void paint(Graphics g) {
		if (g instanceof Graphics2D) {
			doPaint((Graphics2D) g);
		}
	}

	public void paint(GraphicsDecorator g) {
		Graphics2D delegate = g.getDelegate();
		doPaint(delegate);
	}

	private void doPaint(Graphics2D g) {
		if (shapeIsOutdated()) {
			return;
		}

		Color originalColor = g.getColor();
		g.setColor(getColor());

		g.draw(shape);

		g.setColor(Color.black);
		FontMetrics fontMetrics = g.getFontMetrics();
		Rectangle2D stringBounds = fontMetrics.getStringBounds(text, g);
		Point location = shape.getBounds().getLocation();
		location.y += shape.getBounds().height + stringBounds.getBounds().height;
		g.drawString(text, location.x, location.y);

		g.setColor(originalColor);
	}

	private boolean shapeIsOutdated() {
		if (drawingIterationID != drawingIterationCounter.get()) {
			// we are no longer drawing this shape
			SwingUtilities.invokeLater(new Runnable() {
				@Override
				public void run() {
					viewer.removePostRenderPaintable(DebugShape.this);
				}
			});
			return true;
		}
		return false;
	}

	@Override
	public boolean useTransform() {
		return true;
	}
}
