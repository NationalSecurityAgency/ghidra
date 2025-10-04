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
package ghidra.app.decompiler.component.margin;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JPanel;

import docking.util.GraphicsUtils;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import generic.theme.GIcon;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.program.model.listing.Program;

/**
 * The built-in provider for the Decompiler's line number margin
 */
public class LineNumberDecompilerMarginProvider extends JPanel
		implements DecompilerMarginProvider, LayoutModelListener {

	protected static final GIcon OPEN_ICON =
		new GIcon("icon.base.util.viewer.fieldfactory.openclose.open");
	protected static final GIcon CLOSED_ICON =
		new GIcon("icon.base.util.viewer.fieldfactory.openclose.closed");

	private LayoutPixelIndexMap pixmap;
	private LayoutModel model;
	private final DecompilerPanel decompilerPanel;

	public LineNumberDecompilerMarginProvider(DecompilerPanel decompilerPanel) {
		this.decompilerPanel = decompilerPanel;
		setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 2));
		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				handleMouseClick(e);
			}
		});
	}

	@Override
	public void setProgram(Program program, LayoutModel model, LayoutPixelIndexMap pixmap) {
		setLayoutManager(model);
		this.pixmap = pixmap;
		repaint();
	}

	private void setLayoutManager(LayoutModel model) {
		if (this.model == model) {
			return;
		}
		if (this.model != null) {
			this.model.removeLayoutModelListener(this);
		}
		this.model = model;
		setWidthForLastLine();
		if (this.model != null) {
			this.model.addLayoutModelListener(this);
		}
	}

	@Override
	public void setOptions(DecompileOptions options) {
		this.setFont(options.getDefaultFont());
		setWidthForLastLine();
		repaint();
	}

	@Override
	public Component getComponent() {
		return this;
	}

	@Override
	public void modelSizeChanged(IndexMapper indexMapper) {
		setWidthForLastLine();
		repaint();
	}

	@Override
	public void dataChanged(BigInteger start, BigInteger end) {
		repaint();
	}

	private void setWidthForLastLine() {
		if (model == null) {
			return;
		}
		int lastLine = model.getNumIndexes().intValueExact();
		int width = getFontMetrics(getFont()).stringWidth(Integer.toString(lastLine));
		int widthForArrows = getFontMetrics(getFont()).stringWidth(" ") * 2;
		width += widthForArrows;
		Insets insets = getInsets();
		width += insets.left + insets.right;
		setPreferredSize(new Dimension(Math.max(32, width), 0));
		invalidate();
	}

	private void handleMouseClick(MouseEvent e) {
		Insets insets = getInsets();
		int y = e.getY() - insets.top;
		int x = e.getX() - insets.left;

		if (x >= getWidth() - getFontMetrics(getFont()).stringWidth(" ") * 2 - insets.right) {
			decompilerPanel.arrowClickAction(y);
			repaint();
		}
	}

	@Override
	public void paint(Graphics g) {
		super.paint(g);

		Insets insets = getInsets();
		int rightEdge = getWidth() - insets.right - getFontMetrics(getFont()).stringWidth(" ") * 2;
		int leftEdge = insets.left;
		Rectangle visible = getVisibleRect();
		BigInteger startIdx = pixmap.getIndex(visible.y);
		BigInteger endIdx = pixmap.getIndex(visible.y + visible.height);
		int ascent = g.getFontMetrics().getMaxAscent();
		BigInteger lineNumber = startIdx;

		Map<Integer, DecompilerPanel.CodeBlock> blocks = decompilerPanel.getBlocks();
		if (blocks == null) {
			return;
		}

		for (BigInteger i = startIdx; i.compareTo(endIdx) <= 0; i = i.add(BigInteger.ONE)) {
			String text = lineNumber.add(BigInteger.ONE).toString();
			GraphicsUtils.drawString(this, g, text, leftEdge, pixmap.getPixel(i) + ascent);

			BigInteger increment = BigInteger.ONE;

			DecompilerPanel.CodeBlock block = blocks.getOrDefault(lineNumber.intValue(), null);
			if (block != null) {
				// There's a block starting at this line number - check if it's
				// collapsed to determine the icon to draw. If it is collapsed,
				// we also need to skip some number of lines.

				Image img = null;

				if (decompilerPanel.isBlockCollapsed(block.openToken)) {
					// block is collapsed
					increment = BigInteger.valueOf(block.numLines);
					img = CLOSED_ICON.getImageIcon().getImage();
				} else {
					// block is not collapsed
					img = OPEN_ICON.getImageIcon().getImage();
				}

				// Center the image
				int midX = rightEdge + (2 * getFontMetrics(getFont()).stringWidth(" ")) / 2;
				int midY = pixmap.getPixel(i) + (ascent / 2);
				int topLeftX = midX - (img.getWidth(null) / 2);
				int topLeftY = midY - (img.getHeight(null) / 2);

				g.drawImage(img, topLeftX, topLeftY, getBackground(), null);
			}

			lineNumber = lineNumber.add(increment);
		}
	}
}
