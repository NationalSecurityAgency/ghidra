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
package docking.widgets;

import java.awt.*;
import java.awt.event.*;

import javax.swing.JPanel;

import com.google.common.collect.Range;

import ghidra.util.datastruct.ListenerSet;

public class RangeCursorPanel extends JPanel {
	protected final static int MIN_SIZE = 16;
	protected final static Dimension MIN_BOX = new Dimension(MIN_SIZE, MIN_SIZE);

	protected final static Polygon ARROW =
		new Polygon(new int[] { 0, -MIN_SIZE, -MIN_SIZE }, new int[] { 0, MIN_SIZE, -MIN_SIZE }, 3);

	protected static double clamp(Range<Double> range, double value) {
		return Math.max(range.lowerEndpoint(), Math.min(value, range.upperEndpoint()));
	}

	protected enum Orientation {
		HORIZONTAL {
			@Override
			void transform(Component component, Graphics2D g, Range<Double> range, double value) {
				int offset = valueToOffset(component.getWidth(), range, value);
				g.translate(offset, 0);
			}

			@Override
			double getValue(Component component, MouseEvent e, Range<Double> range) {
				return offsetToValue(component.getWidth(), range, e.getX());
			}
		},
		VERTICAL {
			@Override
			void transform(Component component, Graphics2D g, Range<Double> range, double value) {
				g.translate(0, valueToOffset(component.getHeight(), range, value));
			}

			@Override
			double getValue(Component component, MouseEvent e, Range<Double> range) {
				return offsetToValue(component.getHeight(), range, e.getY());
			}
		};

		protected static int valueToOffset(int size, Range<Double> range, double value) {
			double lower = range.lowerEndpoint();
			double length = range.upperEndpoint() - lower;
			double diff = value - lower;
			return (int) (diff * size / length);
		}

		protected static double offsetToValue(int size, Range<Double> range, int offset) {
			double lower = range.lowerEndpoint();
			double length = range.upperEndpoint() - lower;
			double diff = length * offset / size;
			return lower + diff;
		}

		abstract void transform(Component component, Graphics2D g, Range<Double> range,
				double value);

		abstract double getValue(Component component, MouseEvent e, Range<Double> range);
	}

	public enum Direction {
		EAST(Orientation.VERTICAL) {
			@Override
			void transform(Component component, Graphics2D g) {
				g.translate(component.getWidth(), 0);
			}
		},
		NORTH(Orientation.HORIZONTAL) {
			@Override
			void transform(Component component, Graphics2D g) {
				g.rotate(-Math.PI / 2);
			}
		},
		WEST(Orientation.VERTICAL) {
			@Override
			void transform(Component component, Graphics2D g) {
				g.rotate(Math.PI);
			}
		},
		SOUTH(Orientation.HORIZONTAL) {
			@Override
			void transform(Component component, Graphics2D g) {
				g.translate(0, component.getHeight());
				g.rotate(Math.PI / 2);
			}
		};

		protected final Orientation orientation;

		Direction(Orientation orientation) {
			this.orientation = orientation;
		}

		abstract void transform(Component component, Graphics2D g);
	}

	protected final ListenerSet<RangeCursorValueListener> listeners =
		new ListenerSet<>(RangeCursorValueListener.class);

	protected final MouseListener mouseListener = new MouseAdapter() {
		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.getButton() != MouseEvent.BUTTON1) {
				return;
			}
			doSeek(e);
		}
	};

	protected final MouseMotionListener mouseMotionListener = new MouseMotionAdapter() {
		@Override
		public void mouseDragged(MouseEvent e) {
			if ((e.getModifiersEx() & MouseEvent.BUTTON1_DOWN_MASK) == 0) {
				return;
			}
			doSeek(e);
		}
	};

	{
		addMouseListener(mouseListener);
		addMouseMotionListener(mouseMotionListener);
	}

	protected Direction direction;
	protected Range<Double> range = Range.closed(-1.0, 1.0);
	protected double value;

	public RangeCursorPanel(Direction direction) {
		this.direction = direction;
		this.setFocusable(true);
	}

	protected void doSeek(MouseEvent e) {
		double requested = direction.orientation.getValue(RangeCursorPanel.this, e, range);
		requestValue(requested, EventTrigger.GUI_ACTION);
	}

	public void addValueListener(RangeCursorValueListener listener) {
		listeners.add(listener);
	}

	public void removeValueListener(RangeCursorValueListener listener) {
		listeners.remove(listener);
	}

	public void setDirection(Direction direction) {
		this.direction = direction;
		invalidate();
	}

	public void setRange(Range<Double> range) {
		this.range = range;
		repaint();
	}

	public void requestValue(double requested) {
		requestValue(requested, EventTrigger.API_CALL);
	}

	public void requestValue(double requested, EventTrigger trigger) {
		double val = adjustRequestedValue(requested);
		if (this.value == val) {
			return;
		}
		this.value = val;
		listeners.fire.valueChanged(val, trigger);
		repaint();
	}

	public double getValue() {
		return value;
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		Graphics2D g2 = (Graphics2D) g.create();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		//g2.setColor(Color.GREEN);
		//g2.fillPolygon(ARROW);
		direction.orientation.transform(this, g2, range, value);
		//g2.setColor(Color.RED);
		//g2.fillPolygon(ARROW);
		direction.transform(this, g2);
		g2.setColor(getForeground());
		g2.fillPolygon(ARROW);
	}

	protected double adjustRequestedValue(double requested) {
		// Extension point
		return clamp(range, requested);
	}

	@Override
	public Dimension getPreferredSize() {
		return MIN_BOX;
	}

	@Override
	public Dimension getMinimumSize() {
		return MIN_BOX;
	}
}
