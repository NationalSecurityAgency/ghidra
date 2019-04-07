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
package ghidra.graph.viewer.vertex;

import java.awt.Component;
import java.awt.geom.Point2D;

import ghidra.graph.viewer.VisualVertex;

/**
 * A {@link VisualVertex} implementation that implements most of the methods on the interface
 */
public abstract class AbstractVisualVertex implements VisualVertex {

	private boolean focused;
	private boolean selected;
	private boolean hovered;
	private double alpha = 1.0;
	private double emphasis;
	private Point2D location;

	@Override
	public void setFocused(boolean focused) {
		this.focused = focused;
	}

	public boolean isFocused() {
		return focused;
	}

	@Override
	public void setSelected(boolean selected) {
		this.selected = selected;
	}

	@Override
	public boolean isSelected() {
		return selected;
	}

	@Override
	public void setHovered(boolean hovered) {
		this.hovered = hovered;
	}

	@Override
	public boolean isHovered() {
		return hovered;
	}

	@Override
	public void setEmphasis(double emphasisLevel) {
		this.emphasis = emphasisLevel;
	}

	@Override
	public double getEmphasis() {
		return emphasis;
	}

	@Override
	public Point2D getLocation() {
		return location;
	}

	@Override
	public void setLocation(Point2D location) {
		this.location = location;
	}

	@Override
	public void setAlpha(double alpha) {
		this.alpha = alpha;
	}

	@Override
	public double getAlpha() {
		return alpha;
	}

	@Override
	public boolean isGrabbable(Component c) {
		// all parts of a vertex are grabbable by default; subclasses can override
		return true;
	}
}
