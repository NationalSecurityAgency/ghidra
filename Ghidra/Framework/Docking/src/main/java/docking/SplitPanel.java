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
package docking;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;

public class SplitPanel extends JPanel {
	private static int DIVIDER_SIZE = 4;
	private Component leftComp;
	private Component rightComp;
	private Component divider;
	private boolean isHorizontal;
	//private int dividerLocation = Integer.MIN_VALUE;
	private float dividerPosition = 0;

	public SplitPanel(SplitNode splitNode, Component leftComp, Component rightComp,
			boolean isHorizontal) {
		setLayout(new SplitPanelLayout(isHorizontal));
		this.leftComp = leftComp;
		this.rightComp = rightComp;
		this.isHorizontal = isHorizontal;
		divider = new Divider();
		divider.setBackground(Color.LIGHT_GRAY);
		add(leftComp);
		add(divider);
		add(rightComp);
	}

	public boolean isLeft(Component c) {
		return SwingUtilities.isDescendingFrom(c, leftComp);
	}

	float getDividerPosition() {
		return dividerPosition;
	}

	public void setDividerPosition(float newPosition) {
		dividerPosition = newPosition;
		validate();
	}

	class SplitPanelLayout implements LayoutManager {
		boolean horizontal;

		SplitPanelLayout(boolean isHorizontal) {
			this.horizontal = isHorizontal;
		}

		@Override
		public void layoutContainer(Container parent) {
			Dimension size = parent.getSize();
			if (size.width <= 0 || size.height <= 0) {
				return;
			}
			Dimension minSize1 = leftComp.getMinimumSize();
			Dimension minSize2 = rightComp.getMinimumSize();
			Insets insets = parent.getInsets();
			int width = size.width - insets.left - insets.right;
			int height = size.height - insets.top - insets.bottom;

			if (dividerPosition == 0) {
				Dimension d1 = leftComp.getPreferredSize();
				Dimension d2 = rightComp.getPreferredSize();
				Dimension d3 = leftComp.getSize();
				Dimension d4 = rightComp.getSize();
				if (horizontal) {
					if (d3.width > 0 && d4.width > 0) {
						d1 = d3;
						d2 = d4;
					}
					int prefWidth = d1.width + d2.width;
					dividerPosition = (float) d1.width / (float) prefWidth;
				}
				else {
					if (d3.height > 0 && d4.height > 0) {
						d1 = d3;
						d2 = d4;
					}
					int prefHeight = d1.height + d2.height;
					dividerPosition = (float) d1.height / (float) prefHeight;
				}
			}

			if (horizontal) {
				width -= DIVIDER_SIZE;
				int minWidth = minSize1.width + minSize2.width;
				int dividerPixelPosition = Math.round(width * dividerPosition);

				if (width <= minWidth) {
					dividerPosition = (float) minSize1.width / (float) minWidth;
				}
				else if (dividerPixelPosition <= minSize1.width) {
					dividerPosition = (float) minSize1.width / (float) width;
				}
				else if (dividerPixelPosition >= width - minSize2.width) {
					dividerPosition = (float) (width - minSize2.width) / (float) width;
				}

				dividerPixelPosition = Math.round(width * dividerPosition);
				leftComp.setBounds(insets.left, insets.top, dividerPixelPosition, height);
				divider.setBounds(insets.left + dividerPixelPosition, insets.top, DIVIDER_SIZE,
					height);
				rightComp.setBounds(insets.left + dividerPixelPosition + DIVIDER_SIZE, insets.top,
					width - dividerPixelPosition, height);
			}
			else {
				height -= DIVIDER_SIZE;
				int minHeight = minSize1.height + minSize2.height;
				int dividerPixelPosition = Math.round(height * dividerPosition);

				if (height <= minHeight) {
					dividerPosition = (float) minSize1.height / (float) minHeight;
				}
				else if (dividerPixelPosition <= minSize1.height) {
					dividerPosition = (float) minSize1.height / (float) height;
				}
				else if (dividerPixelPosition >= height - minSize2.height) {
					dividerPosition = (float) (height - minSize2.height) / (float) height;
				}

				dividerPixelPosition = Math.round(height * dividerPosition);

				leftComp.setBounds(insets.left, insets.top, width, dividerPixelPosition);
				divider.setBounds(insets.left, insets.top + dividerPixelPosition, width,
					DIVIDER_SIZE);
				rightComp.setBounds(insets.left, dividerPixelPosition + DIVIDER_SIZE + insets.top,
					width, height - dividerPixelPosition);

			}
		}

		@Override
		public Dimension minimumLayoutSize(Container parent) {
			Dimension d1 = leftComp.getMinimumSize();
			Dimension d2 = rightComp.getMinimumSize();
			Insets insets = parent.getInsets();
			if (horizontal) {
				return new Dimension(
					d1.width + d2.width + DIVIDER_SIZE + insets.left + insets.right,
					Math.max(d1.height, d2.height) + insets.top + insets.bottom);
			}
			return new Dimension(Math.max(d1.width, d2.width) + insets.left + insets.right,
				d1.height + d2.height + DIVIDER_SIZE + insets.top + insets.bottom);
		}

		@Override
		public Dimension preferredLayoutSize(Container parent) {
			Dimension d1 = leftComp.getPreferredSize();
			Dimension d2 = rightComp.getPreferredSize();
			Insets insets = parent.getInsets();
			if (horizontal) {
				return new Dimension(
					d1.width + d2.width + DIVIDER_SIZE + insets.left + insets.right,
					Math.max(d1.height, d2.height) + insets.top + insets.bottom);
			}
			return new Dimension(Math.max(d1.width, d2.width) + insets.left + insets.right,
				d1.height + d2.height + DIVIDER_SIZE + insets.top + insets.bottom);
		}

		@Override
		public void addLayoutComponent(String name, Component comp) {
		}

		@Override
		public void removeLayoutComponent(Component comp) {
		}
	}

	class Divider extends JPanel {
		Divider() {
			if (isHorizontal) {
				setCursor(Cursor.getPredefinedCursor(Cursor.W_RESIZE_CURSOR));
			}
			else {
				setCursor(Cursor.getPredefinedCursor(Cursor.N_RESIZE_CURSOR));
			}

			addMouseMotionListener(new MouseMotionAdapter() {
				@Override
				public void mouseDragged(MouseEvent e) {
					if (isHorizontal) {
						dividerPosition += (float) e.getX() / (float) SplitPanel.this.getWidth();
					}
					else {
						dividerPosition += (float) e.getY() / (float) SplitPanel.this.getHeight();
					}

					SplitPanel.this.doLayout();
					SplitPanel.this.validate();
				}
			});
		}

	}
}
