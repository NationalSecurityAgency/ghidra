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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import javax.swing.JPanel;

import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.component.margin.DecompilerMarginProvider;
import ghidra.app.decompiler.component.margin.LayoutPixelIndexMap;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public class BreakpointsDecompilerMarginProvider extends JPanel
		implements DecompilerMarginProvider, LayoutModelListener {

	private Program program;
	private LayoutModel model;
	private LayoutPixelIndexMap pixmap;

	private final DebuggerBreakpointMarkerPlugin plugin;

	public BreakpointsDecompilerMarginProvider(DebuggerBreakpointMarkerPlugin plugin) {
		this.plugin = plugin;
		setPreferredSize(new Dimension(16, 0));
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				doToggleBreakpoint(e);
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

	@Override
	public void paint(Graphics g) {
		super.paint(g);
		if (plugin.breakpointService == null) {
			return;
		}
		Rectangle visible = getVisibleRect();
		BigInteger startIdx = pixmap.getIndex(visible.y);
		BigInteger endIdx = pixmap.getIndex(visible.y + visible.height);

		List<ClangLine> lines = plugin.decompilerMarginService.getDecompilerPanel().getLines();
		for (BigInteger index = startIdx; index.compareTo(endIdx) <= 0; index =
			index.add(BigInteger.ONE)) {
			int i = index.intValue();
			if (i >= lines.size()) {
				continue;
			}
			ClangLine line = lines.get(i);
			List<ProgramLocation> locs =
				DebuggerBreakpointMarkerPlugin.getLocationsFromLine(program, line);
			State state = plugin.computeState(locs);
			if (state.icon != null) {
				state.icon.paintIcon(this, g, 0, pixmap.getPixel(index));
			}
		}
	}

	private void doToggleBreakpoint(MouseEvent e) {
		if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
			int i = pixmap.getIndex(e.getY()).intValue();
			List<ClangLine> lines = plugin.decompilerMarginService.getDecompilerPanel().getLines();
			List<ProgramLocation> locs =
				DebuggerBreakpointMarkerPlugin.nearestLocationsToLine(program, i, lines);
			if (locs == null || locs.isEmpty()) {
				return;
			}
			Set<LogicalBreakpoint> col = plugin.collectBreakpoints(locs);
			plugin.breakpointService.toggleBreakpointsAt(col, locs.get(0), () -> {
				plugin.placeBreakpointDialog.prompt(plugin.getTool(), plugin.breakpointService,
					"Set breakpoint", locs.get(0), 1, Set.of(TraceBreakpointKind.SW_EXECUTE), "");
				// Not great, but I'm not sticking around for the dialog
				return CompletableFuture.completedFuture(Set.of());
			});
		}
	}
}
