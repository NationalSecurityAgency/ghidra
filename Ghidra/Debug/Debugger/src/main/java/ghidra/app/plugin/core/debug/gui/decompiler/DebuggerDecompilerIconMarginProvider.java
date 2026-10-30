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
package ghidra.app.plugin.core.debug.gui.decompiler;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JPanel;

import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.component.margin.DecompilerMarginProvider;
import ghidra.app.decompiler.component.margin.LayoutPixelIndexMap;
import ghidra.program.model.listing.Program;

/**
 * A Decompiler margin that paints the icons of every {@link DecompilerMarginIconSource} added to
 * the {@link DebuggerDecompilerMarginService}
 */
public class DebuggerDecompilerIconMarginProvider extends JPanel
		implements DecompilerMarginProvider, LayoutModelListener {

	private Program program;
	private LayoutModel model;
	private LayoutPixelIndexMap pixmap;

	private final DebuggerDecompilerMarginServicePlugin plugin;

	public DebuggerDecompilerIconMarginProvider(DebuggerDecompilerMarginServicePlugin plugin) {
		this.plugin = plugin;
		setPreferredSize(new Dimension(16, 0));
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				doMarginPressed(e);
			}
		});
	}

	@Override
	public void setProgram(Program program, LayoutModel model, LayoutPixelIndexMap pixmap) {
		this.program = program;
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
		if (this.model != null) {
			this.model.addLayoutModelListener(this);
		}
	}

	@Override
	public Component getComponent() {
		return this;
	}

	@Override
	public void modelSizeChanged(IndexMapper indexMapper) {
		repaint();
	}

	@Override
	public void dataChanged(BigInteger start, BigInteger end) {
		repaint();
	}

	/**
	 * Get the icons for the given line, in the order they are painted
	 *
	 * @param line the line
	 * @return the icons, lowest priority first
	 */
	List<Icon> getIcons(ClangLine line) {
		if (program == null) {
			return List.of();
		}
		List<DecompilerMarginIconSource> sources = new ArrayList<>(plugin.sources);
		sources.sort(Comparator.comparingInt(DecompilerMarginIconSource::getPriority));
		List<Icon> icons = new ArrayList<>();
		for (DecompilerMarginIconSource source : sources) {
			Icon icon = source.getIcon(program, line);
			if (icon != null) {
				icons.add(icon);
			}
		}
		return icons;
	}

	@Override
	public void paint(Graphics g) {
		super.paint(g);
		if (pixmap == null) {
			return;
		}
		Rectangle visible = getVisibleRect();
		BigInteger startIdx = pixmap.getIndex(visible.y);
		BigInteger endIdx = pixmap.getIndex(visible.y + visible.height);

		List<ClangLine> lines = plugin.getLines();
		for (BigInteger index = startIdx; index.compareTo(endIdx) <= 0; index =
			index.add(BigInteger.ONE)) {
			int i = index.intValue();
			if (i >= lines.size()) {
				continue;
			}
			for (Icon icon : getIcons(lines.get(i))) {
				icon.paintIcon(this, g, 0, pixmap.getPixel(index));
			}
		}
	}

	private void doMarginPressed(MouseEvent e) {
		if (pixmap == null || program == null) {
			return;
		}
		int i = pixmap.getIndex(e.getY()).intValue();
		List<ClangLine> lines = plugin.getLines();
		for (DecompilerMarginIconSource source : plugin.sources) {
			source.marginPressed(program, i, lines, e);
		}
	}
}
