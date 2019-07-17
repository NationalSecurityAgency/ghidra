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
package ghidra.app.util;

import java.awt.*;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.app.util.viewer.util.AddressPixelMap;
import ghidra.program.model.mem.MemoryBlock;

public class BlockPanel extends JPanel implements ComponentListener {
	private static final long serialVersionUID = 1L;
	private static final int SPACING = 5;
	private static final Font FONT = new Font("SansSerif", Font.PLAIN, 10);
	private AddressPixelMap map;
	private FontMetrics metrics;

	public BlockPanel() {
		super();
		setBackground(Color.WHITE);
		addComponentListener(this);
		metrics = getFontMetrics(FONT);
		setPreferredSize(
			new Dimension(100, SPACING + metrics.getMaxAscent() + metrics.getMaxDescent()));
	}

	@Override
	public void paintComponent(Graphics g) {

		g.setColor(Color.BLACK);
		g.setFont(FONT);
		int height = getHeight();

		MemoryBlock[] blocks = map.getBlocks();
		if (blocks == null) {
			return;
		}

		for (int i = 0; i < blocks.length; i++) {
			Rectangle rect = map.getBlockPosition(blocks[i]);
			g.drawLine(rect.x, 0, rect.x, height - 1);
		}
		g.drawLine(getWidth() - 1, 0, getWidth() - 1, height - 1);

		g.drawLine(0, height - 1, getWidth() - 1, height - 1);
	}

	@Override
	protected void paintChildren(Graphics g) {
		//
		// clear the background; paint our labels; paint our divider lines
		//
		Color oldColor = g.getColor();
		g.setColor(getBackground());
		Rectangle clip = g.getClipBounds();
		g.fillRect(clip.x, clip.y, clip.width, clip.height);
		g.setColor(oldColor);
		super.paintChildren(g);
		paintComponent(g);
	}

	public void setMemoryBlockMap(AddressPixelMap map) {
		this.map = map;
		repaint();
	}

	/** Creates labels for the block names */
	private void buildLabels() {
		removeAll();
		setLayout(null);

		Container parent = getParent();

		MemoryBlock[] blocks = map.getBlocks();
		if (blocks == null) {
			return;
		}

		for (MemoryBlock block : blocks) {
			JLabel label = new GDLabel(block.getName());
			label.setFont(FONT);
			label.setHorizontalAlignment(SwingConstants.CENTER);
			label.setToolTipText(block.getName());

			Rectangle rect = map.getBlockPosition(block);
			int height = getHeight();
			int width = metrics.stringWidth(block.getName());
			if (rect.width < width) {
				label.setText("...");
			}
			int labelWidth = Math.min(rect.width, width);
			labelWidth = Math.max(labelWidth, 3);
			int labelHeight = height - 1;
			int x = rect.x + (rect.width - 1) / 2 - labelWidth / 2;
			int y = 0;

			label.setBounds(x, y, labelWidth, labelHeight);
			add(label);
		}
		invalidate();
		if (parent != null) {
			parent.validate();
		}
	}

	public void refresh() {
		buildLabels();
		repaint();
	}

	@Override
	public void componentResized(ComponentEvent e) {
		refresh();
	}

	@Override
	public void componentHidden(ComponentEvent e) {
	}

	@Override
	public void componentMoved(ComponentEvent e) {
	}

	@Override
	public void componentShown(ComponentEvent e) {
	}
}
