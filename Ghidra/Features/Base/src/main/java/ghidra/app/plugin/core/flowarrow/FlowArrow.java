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
package ghidra.app.plugin.core.flowarrow;

import java.awt.*;
import java.awt.geom.PathIterator;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.symbol.RefType;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

abstract class FlowArrow {

	private static final int MIN_LINE_SPACING = 9;
	private static final int DEFAULT_LINE_SPACING = 16;
	private static final int MAX_LINE_SPACING = 60;
	/** The amount of space between arrows, as a percentage of the available width */
	private static final double ARROW_SPACING_RATIO = .18;

	Address start;
	Address end;
	AddressSet addressSet;
	int depth = -1;
	RefType refType;
	private boolean isUp;

	boolean active;
	boolean selected;

	private FlowArrowPlugin plugin;
	private Component canvas;
	protected Shape arrowBody;
	protected Shape arrowHead;

	/** The shape of the arrow body, but with added size */
	private List<Shape> clickableShapes = new ArrayList<>();

	FlowArrow(FlowArrowPlugin plugin, Component canvas, Address start, Address end,
			RefType referenceType) {
		this.plugin = plugin;
		this.canvas = canvas;
		this.start = start;
		this.end = end;
		this.refType = referenceType;
		this.addressSet = new AddressSet(new AddressRangeImpl(start, end));
		isUp = start.compareTo(end) > 0;
	}

	abstract Stroke getSelectedStroke();

	abstract Stroke getActiveStroke();

	abstract Stroke getInactiveStroke();

	void paint(Graphics2D g2, Color fgColor, Color bgColor) {
		if (arrowBody == null) {
			createShapes();
		}

		doPaint(g2, fgColor, bgColor);
	}

	private void doPaint(Graphics2D g2, Color fgColor, Color bgColor) {
		Paint oldPaint = g2.getPaint();
		Stroke oldStroke = g2.getStroke();

		g2.setPaint(fgColor);
		if (selected) {
			g2.setStroke(getSelectedStroke());
		}
		else if (active) {
			g2.setStroke(getActiveStroke());
		}
		else {
			g2.setStroke(getInactiveStroke());
		}

		g2.draw(arrowBody);
		g2.fill(arrowHead);

		//	g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_OFF);

		g2.setPaint(oldPaint);
		g2.setStroke(oldStroke);
	}

	/** True if this arrow points up instead of down */
	boolean isUp() {
		return isUp;
	}

	/** Call when the screen moves so that the shape can be updated */
	void resetShape() {
		arrowBody = null;
		arrowHead = null;
		clickableShapes.clear();
	}

	boolean intersects(Point p) {
		// make the point a bit bigger, so the line is easier to hit
		double size = 5;
		double half = size / 2;
		double x = p.x - half;
		double y = p.y - half;

		Rectangle2D pickArea = new Rectangle2D.Double(x, y, size, size);
		if (intersectsAnyPartOfArrow(pickArea)) {
			return true;
		}

		return false;
	}

	private boolean intersectsAnyPartOfArrow(Rectangle2D area) {

		if (arrowBody == null) {
			createShapes();
		}

		if (clickableShapes.isEmpty()) {
			createClickableShapes();
		}

		for (Shape s : clickableShapes) {
			if (s.intersects(area)) {
				return true;
			}
		}

		if (arrowHead.intersects(area)) {
			// we know the arrow head has size
			return true;
		}

		return false;
	}

	private void createClickableShapes() {
		List<Shape> shapes = new ArrayList<>();
		Rectangle r = null;
		PathIterator it = arrowBody.getPathIterator(null);
		float[] coords = new float[6];
		double lastx = 0;
		double lasty = 0;
		while (!it.isDone()) {
			int type = it.currentSegment(coords);
			switch (type) {
				case (PathIterator.SEG_MOVETO):
					if (r != null) {
						throw new AssertException("Founds a flow arrow shape without a line");
					}

					r = new Rectangle((int) coords[0], (int) coords[1], 0, 0);
					break;
				case (PathIterator.SEG_LINETO):

					// handle drawing from line-to-line, without a move
					if (r == null) {
						// not sure if this ever happens
						r = new Rectangle((int) lastx, (int) lasty);
					}

					lastx = coords[0];
					lasty = coords[1];
					Rectangle shape = buildRectangle(r, lastx, lasty);
					shapes.add(shape);
					r = null;
					break;
				case (PathIterator.SEG_CLOSE):
					if (r != null) {
						throw new AssertException("Founds a flow arrow shape without a line");
					}
					break;
				default:
					throw new AssertException("Unhandled path type!");
			}
			it.next();
		}

		clickableShapes = shapes;
	}

	private Rectangle buildRectangle(Rectangle r, double endx, double endy) {

		double x = r.x;
		double y = r.y;

		double w = Math.abs(x - endx);
		double h = Math.abs(y - endy);

		if (w != 0 && h != 0) {
			// already has a size; don't alter it
			r.setSize((int) w, (int) h);
			return r;
		}

		if (h == 0) { // add some height

			if (x > endx) {
				// right-to-left; swap x values, since rectangles are l-to-r
				x = endx;
			}

			y -= 1;
			h = 2;
		}
		else { // add some width

			if (y > endy) {
				// bottom-to-top; swap y values, since rectangles are t-to-b
				y = endy;
			}

			x -= 1;
			w = 2;
		}

		r.setFrame(x, y, w, h);
		return r;
	}

	private void createShapes() {

		int displayHeight = canvas.getHeight();
		int displayWidth = canvas.getWidth();// - FlowArrowPlugin.LEFT_OFFSET;
		int lineWidth = calculateLineWidth(displayWidth);

		arrowBody = FlowArrowShapeFactory.createArrowBody(plugin, this, displayWidth, displayHeight,
			lineWidth);

		arrowHead = FlowArrowShapeFactory.createArrowHead(plugin, this, displayWidth, displayHeight,
			lineWidth);
	}

	private int calculateLineWidth(int displayWidth) {
		// Crunch or stretch spacing depending upon width and maximum depth
		int lineWidth = DEFAULT_LINE_SPACING;
		int maxDepth = plugin.getMaxDepth();

		if (maxDepth >= 0) {
			int availabeWidth = displayWidth - FlowArrowPlugin.LEFT_OFFSET;
			lineWidth = (int) (availabeWidth * ARROW_SPACING_RATIO);
		}
		if (lineWidth < MIN_LINE_SPACING) {
			lineWidth = MIN_LINE_SPACING;
		}
		else if (lineWidth > MAX_LINE_SPACING) {
			lineWidth = MAX_LINE_SPACING;
		}

		return lineWidth;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((end == null) ? 0 : end.hashCode());
		result = prime * result + ((refType == null) ? 0 : refType.hashCode());
		result = prime * result + ((start == null) ? 0 : start.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		FlowArrow other = (FlowArrow) obj;
		if (end == null) {
			if (other.end != null) {
				return false;
			}
		}
		else if (!end.equals(other.end)) {
			return false;
		}
		if (refType == null) {
			if (other.refType != null) {
				return false;
			}
		}
		else if (!refType.equals(other.refType)) {
			return false;
		}
		if (start == null) {
			if (other.start != null) {
				return false;
			}
		}
		else if (!start.equals(other.start)) {
			return false;
		}
		return true;
	}

	public String getDisplayString() {
		return "<html><table><tr><td>start</td><td>" + HTMLUtilities.escapeHTML(start.toString()) +
			"</td><tr><td>end</td><td>" + HTMLUtilities.escapeHTML(end.toString()) +
			"</td><tr><td>ref type</td><td>" + refType + "</td></tr></table>";
	}

	@Override
	public String toString() {
		return "start=" + start + "; end=" + end + "; ref type=" + refType;
	}
}
