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
package ghidra.app.plugin.core.debug.gui.internal;

import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.tree.TreePath;

import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.gui.internal.RStarTreeProvider.HasShape;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.Painter;
import ghidra.trace.model.*;
import ghidra.util.database.spatial.DBTreeDataRecord;

public class RStarPlotProvider extends ComponentProviderAdapter {
	private final RStarDiagnosticsPlugin plugin;

	final JComponent component = new JPanel(true) {
		@Override
		public void paint(Graphics g) {
			super.paint(g);
			RStarPlotProvider.this.doPaint(g);
		}
	};

	private int depth = RStarDiagnosticsPlugin.INITIAL_DEPTH;

	TraceAddressSnapRange bounds;
	private int mouseX;
	private int mouseY;

	private boolean didDrag;
	private int begDragX;
	private int begDragY;
	private int endDragX;
	private int endDragY;

	public RStarPlotProvider(RStarDiagnosticsPlugin plugin) {
		super(plugin.getTool(), "R*-Tree Diagnostic Plot", plugin.getName());
		this.plugin = plugin;
		updateSubtitle();
		component.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				component.repaint();
			}

			@Override
			public void componentShown(ComponentEvent e) {
				component.repaint();
			}
		});

		component.addMouseWheelListener(new MouseWheelListener() {
			@Override
			public void mouseWheelMoved(MouseWheelEvent e) {
				if (plugin.space == null) {
					return;
				}
				int maxDepth = plugin.space.getDepth();
				int newDepth =
					Math.min(
						Math.max(depth + e.getWheelRotation(), RStarDiagnosticsPlugin.MIN_DEPTH),
						maxDepth);
				if (newDepth == depth) {
					return;
				}
				depth = newDepth;
				updateSubtitle();
				component.repaint();
			}
		});
		component.addMouseMotionListener(new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				if (plugin.space == null) {
					return;
				}
				OffsetSnap offsetSnap = xyToOffsetSnap(e.getX(), e.getY());
				if (offsetSnap == null) {
					return;
				}
				tool.setStatusInfo(offsetSnap.toString());
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				didDrag = true;
			}
		});
		component.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() == 1) {
					mouseX = e.getX();
					mouseY = e.getY();
					component.repaint();
				}
				else if (e.getButton() == 3) {
					if (plugin.space == null) {
						bounds = null;
					}
					else {
						bounds = plugin.space.getRootBounds();
					}
					component.repaint();
				}
			}

			@Override
			public void mousePressed(MouseEvent e) {
				didDrag = false;
				begDragX = e.getX();
				begDragY = e.getY();
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (!didDrag) {
					return;
				}
				endDragX = e.getX();
				endDragY = e.getY();
				if (endDragX == begDragX || endDragY == begDragY) {
					return;
				}
				if (endDragX < begDragX) {
					int t = endDragX;
					endDragX = begDragX;
					begDragX = t;
				}
				if (endDragY < begDragY) {
					int t = endDragY;
					endDragY = begDragY;
					begDragY = t;
				}
				Trace trace = plugin.current.getTrace();
				if (trace == null) {
					return;
				}
				AddressSpace addrSpace = trace.getBaseAddressFactory().getDefaultAddressSpace();
				OffsetSnap beg = xyToOffsetSnap(begDragX, begDragY);
				OffsetSnap end = xyToOffsetSnap(endDragX, endDragY);
				bounds =
					new ImmutableTraceAddressSnapRange(addrSpace.getAddress(beg.offset),
						addrSpace.getAddress(end.offset), beg.snap, end.snap);
				component.repaint();
			}
		});
		new ActionBuilder("Zoom Out", plugin.getName())
				.toolBarIcon(new GIcon("icon.debugger.breakpoint.timeline.zoom_out_max"))
				.onAction(ctx -> {
					if (plugin.space == null) {
						bounds = null;
					}
					else {
						bounds = plugin.space.getRootBounds();
					}
				})
				.buildAndInstallLocal(this);
	}

	record OffsetSnap(long offset, long snap) {
		@Override
		public final String toString() {
			return "Addr:%08x,Snap:%d".formatted(offset, snap);
		}
	}

	protected OffsetSnap xyToOffsetSnap(int x, int y) {
		if (bounds == null) {
			return null;
		}
		double scaleX =
			1.0 * (bounds.getX2().getOffset() - bounds.getX1().getOffset()) /
				component.getWidth();
		double scaleY = 1.0 * (bounds.getY2() - bounds.getY1()) / component.getHeight();

		long offset = bounds.getX1().getOffset() + (long) (scaleX * x);
		long snap = bounds.getY1() + (long) (scaleY * y);
		return new OffsetSnap(offset, snap);
	}

	protected void updateSubtitle() {
		if (plugin.space == null) {
			setSubTitle("");
			return;
		}
		setSubTitle("Depth=%d,Max=%d".formatted(depth, plugin.space.getDepth()));
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private abstract class MyPainter implements Painter {
		private final double xScale;
		private final double yScale;
		private final long xShift;
		private final long yShift;

		public MyPainter(Rectangle rect, TraceAddressSnapRange bounds) {
			xScale = 1.0 * rect.width / (bounds.getX2().getOffset() - bounds.getX1().getOffset());
			yScale = 1.0 * rect.height / (bounds.getY2() - bounds.getY1());
			xShift = bounds.getX1().getOffset();
			yShift = bounds.getY1();
		}

		@Override
		public void paint(TraceAddressSnapRange shape, int depth) {
			int x = (int) ((shape.getX1().getOffset() - xShift) * xScale);
			int y = (int) ((shape.getY1() - yShift) * yScale);

			int width = Math.max(1,
				(int) ((shape.getX2().getOffset() - shape.getX1().getOffset()) * xScale));
			int height = Math.max(1, (int) ((shape.getY2() - shape.getY1()) * yScale));

			paintRect(x, y, width, height, shape, depth);
		}

		protected abstract void paintRect(int x, int y, int width, int height,
				TraceAddressSnapRange shape, int depth);
	}

	void doPaint(Graphics _g) {
		if (!(_g instanceof Graphics2D g)) {
			return;
		}
		Rectangle r = new Rectangle(0, 0, component.getWidth(), component.getHeight());
		g.clearRect(r.x, r.y, r.width, r.height);
		if (plugin.space == null) {
			return;
		}
		if (bounds == null) {
			bounds = plugin.space.getRootBounds();
		}

		var fillPainter = new MyPainter(r, bounds) {
			TraceAddressSnapRange result;

			@Override
			protected void paintRect(int x, int y, int width, int height,
					TraceAddressSnapRange shape, int depth) {
				boolean select = x <= mouseX && mouseX <= x + width &&
					y <= mouseY && mouseY <= y + height;
				float brightness = (float) Math.pow(0.5, depth);
				if (select) {
					result = shape;
					g.setColor(shape instanceof DBTreeDataRecord<?, ?, ?>
							? new Color(0, brightness, 0)
							: new Color(0, brightness, brightness));
				}
				else {
					g.setColor(shape instanceof DBTreeDataRecord<?, ?, ?>
							? new Color(brightness, brightness, 0)
							: new Color(brightness, brightness, brightness));
				}
				g.fillRect(x, y, width, height);
			}
		};
		var linePainter = new MyPainter(r, bounds) {
			@Override
			protected void paintRect(int x, int y, int width, int height,
					TraceAddressSnapRange shape, int depth) {
				g.setColor(shape instanceof DBTreeDataRecord<?, ?, ?>
						? Color.RED
						: Color.BLACK);
				g.drawRect(x, y, width, height);
			}
		};

		TreePath[] selArr = plugin.treeProvider.tree.getSelectionPaths();
		if (selArr == null || selArr.length == 0) {
			plugin.space.paint(fillPainter, depth);
			plugin.space.paint(linePainter, depth);
			if (fillPainter.result != null) {
				plugin.treeProvider.select(fillPainter.result);
			}
		}

		List<TreePath> selection = Arrays.asList(selArr);
		selection.sort((p1, p2) -> {
			return p1.getPathCount() - p2.getPathCount();
		});
		g.setColor(Color.CYAN);
		for (TreePath p : selection) {
			if (!(p.getLastPathComponent() instanceof HasShape node)) {
				continue;
			}
			fillPainter.paint(node.getShape(), p.getPathCount() - 1);
		}
		for (TreePath p : selection) {
			if (!(p.getLastPathComponent() instanceof HasShape node)) {
				continue;
			}
			linePainter.paint(node.getShape(), p.getPathCount() - 1);
		}
	}
}
