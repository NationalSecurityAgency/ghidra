/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.geom.Point2D;

import org.jdom.Element;

class PointInfo {

	static final String POINT_INFO_ELEMENT_NAME = "POINT_INFO";

	private static final String X = "X";
	private static final String Y = "Y";
	String x;
	String y;

	PointInfo(Point2D point) {
		x = Double.toString(point.getX());
		y = Double.toString(point.getY());
	}

	PointInfo(Element element) {
		x = element.getAttributeValue(X);
		y = element.getAttributeValue(Y);

		if (x == null) {
			throw new NullPointerException("Error reading XML for " + getClass().getName());
		}

		if (y == null) {
			throw new NullPointerException("Error reading XML for " + getClass().getName());
		}
	}

	Point2D getPoint() {
		return new Point2D.Double(Double.valueOf(x), Double.valueOf(y));
	}

	void write(Element parent) {
		Element element = new Element(POINT_INFO_ELEMENT_NAME);
		element.setAttribute(X, x);
		element.setAttribute(Y, y);
		parent.addContent(element);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[x=" + x + "y=" + y + "]";
	}
}
