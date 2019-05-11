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

import java.awt.*;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Ellipse2D.Double;
import java.awt.image.BufferedImage;

import javax.swing.*;

import ghidra.graph.algo.GraphAlgorithmStatusListener.STATUS;
import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.viewer.vertex.VertexShapeProvider;

public class AlgorithmTestSteppingVertex<V> extends AbstractTestVertex
		implements VertexShapeProvider {

	private ShapeImage defaultShape;
	private ShapeImage defaultWithPathShape;
	private ShapeImage scheduledShape;
	private ShapeImage exploringShape;
	private ShapeImage blockedShape;
	private ShapeImage currentShape;

	private JLabel tempLabel = new JLabel();
	private V v;
	private STATUS status = STATUS.WAITING;

	private boolean wasEverInPath;

	protected AlgorithmTestSteppingVertex(V v) {
		super(v.toString());
		this.v = v;

		buildShapes();

		tempLabel.setText(v.toString());
	}

	public void setStatus(STATUS status) {
		this.status = status;

		ShapeImage si;
		switch (status) {
			case BLOCKED:
				si = blockedShape;
				if (wasEverInPath) {
					si = defaultWithPathShape;
				}
				break;
			case EXPLORING:
				si = exploringShape;
				break;
			case SCHEDULED:
				si = scheduledShape;
				break;
			case IN_PATH:
				si = exploringShape;
				wasEverInPath = true;
				break;
			case WAITING:
			default:
				si = defaultShape;
				if (wasEverInPath) {
					si = defaultWithPathShape;
				}
				break;
		}

		currentShape = si;
	}

	private void buildShapes() {

		defaultShape = buildCircleShape(Color.LIGHT_GRAY, "default");
		defaultWithPathShape = buildCircleShape(new Color(192, 216, 65), "default; was in path");
		scheduledShape = buildCircleShape(new Color(255, 248, 169), "scheduled");
		exploringShape = buildCircleShape(new Color(0, 147, 0), "exploring");
		blockedShape = buildCircleShape(new Color(249, 190, 190), "blocked");

		currentShape = defaultShape;
	}

	private ShapeImage buildCircleShape(Color color, String name) {
		int w = 50;
		int h = 50;

		Double circle = new Ellipse2D.Double(0, 0, w, h);

		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2 = (Graphics2D) image.getGraphics();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		g2.setColor(color);
		g2.fill(circle);

		g2.dispose();

		Dimension shapeSize = circle.getBounds().getSize();
		int x = 50;
		int y = 0;
		circle.setFrame(x, y, shapeSize.width, shapeSize.height);

		return new ShapeImage(image, circle, name);
	}

	V getTestVertex() {
		return v;
	}

	@Override
	public JComponent getComponent() {
		ShapeImage si = getShapeImage();
		ImageIcon icon = new ImageIcon(si.getImage());
		tempLabel.setIcon(icon);
		return tempLabel;
	}

	private ShapeImage getShapeImage() {
		return currentShape;
	}

	@Override
	public Shape getCompactShape() {
		return getShapeImage().getShape();
	}

	@Override
	public String toString() {
		String statusString = status.toString();
		if (wasEverInPath) {
			statusString = "";
		}
		else if (status == STATUS.BLOCKED) {
			statusString = "";
		}

		return v.toString() + " " + statusString;
	}

	private class ShapeImage {
		private Image image;
		private Shape shape;
		private String shapeName;

		ShapeImage(Image image, Shape shape, String name) {
			this.image = image;
			this.shape = shape;
			this.shapeName = name;
		}

		Shape getShape() {
			return shape;
		}

		Image getImage() {
			return image;
		}

		String getName() {
			return shapeName;
		}

		@Override
		public String toString() {
			return getName();
		}
	}
}
