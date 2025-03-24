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
package ghidra.app.plugin.core.debug.gui.timeoverview;

import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.TreeSet;

import javax.swing.*;

import docking.action.DockingActionIf;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Lifespan;
import ghidra.util.task.SwingUpdateManager;

/**
 * Overview bar component. Uses color to indicate various snap-based properties for a program.
 * Uses an {@link TimeOverviewColorService} to get the appropriate color for a snaps.
 */
public class TimeOverviewColorComponent extends JPanel implements OverviewProvider {
	private static final Color DEFAULT_COLOR = Color.GRAY;
	protected TimeOverviewColorService service;
	private Color[] colorsByPixel = new Color[0];
	private final SwingUpdateManager refreshUpdater =
		new SwingUpdateManager(100, 15000, () -> doRefresh());

	private PluginTool tool;
	private List<DockingActionIf> actions;
	private TimeOverviewColorPlugin plugin;

	/**
	 * Constructor
	 *
	 * @param tool the PluginTool
	 * @param overviewColorService the {@link TimeOverviewColorService} that provides colors for
	 *            various snaps.
	 */
	public TimeOverviewColorComponent(PluginTool tool,
			TimeOverviewColorService overviewColorService) {
		this.tool = tool;
		this.service = overviewColorService;
		overviewColorService.setOverviewComponent(this);
		addMouseListener(new MouseAdapter() {
			private int pressedY;
			private boolean enableDrag = false;

			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON1) {
					Long snap = service.getSnap(e.getY());
					gotoSnap(snap);
				}
			}

			@Override
			public void mousePressed(MouseEvent e) {
				enableDrag = true;
				pressedY = e.getY();
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (enableDrag) {
					Long start = service.getSnap(pressedY);
					Long stop = service.getSnap(e.getY());
					if (start == null || stop == null) {
						return;
					}
					Lifespan span;
					if ((e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0) {
						Lifespan prev = getLifespan();
						if (prev != null) {
							int shift = stop.intValue() - start.intValue();
							span = Lifespan.span(prev.lmin() - shift, prev.lmax() - shift);
						}
						else {
							span = prev;
						}
					}
					else {
						if (start > stop) {
							Long tmp = stop;
							stop = start;
							start = tmp;
						}
						span  = Lifespan.span(start, stop);
					}
					plugin.setLifespan(span);
					enableDrag = false;
				}
			}

		});
		ToolTipManager.sharedInstance().registerComponent(this);
		actions = service.getActions();
	}

	/**
	 * Installs actions for this component
	 */
	public void installActions() {
		if (actions == null) {
			return;
		}
		for (DockingActionIf action : actions) {
			tool.addAction(action);
		}
	}

	/**
	 * Removes previous installed actions for this component.
	 */
	public void uninstallActions() {
		if (actions == null) {
			return;
		}
		for (DockingActionIf action : actions) {
			tool.removeAction(action);
		}
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(16, 1);
	}

	protected void gotoSnap(Long snap) {
		plugin.gotoSnap(snap);
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		Long snap = service.getSnap(e.getY());
		return service.getToolTipText(snap);
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		int width = getWidth();
		int pixelCount = getOverviewPixelCount();

		g.setColor(getBackground());
		g.fillRect(0, 0, width - 1, getHeight() - 1);

		if (service.getTrace() == null) {
			return;
		}

		for (int i = 0; i < pixelCount; i++) {
			Color color = getColor(i);
			g.setColor(color);
			g.fillRect(1, i, width - 3, 1);
		}
		if (colorsByPixel.length != pixelCount) {
			colorsByPixel = new Color[pixelCount];
			refreshUpdater.updateLater();
		}
	}

	private Color getColor(int index) {
		if (colorsByPixel != null && index < colorsByPixel.length) {
			return colorsByPixel[index];
		}
		return DEFAULT_COLOR;
	}

	public int getOverviewPixelCount() {
		return Math.max(getHeight(), 0);
	}

	private void doRefresh() {
		for (int i = 0; i < colorsByPixel.length; i++) {
			if (colorsByPixel[i] == null) {
				Long snap = service.getSnap(i);
				colorsByPixel[i] = service.getColor(snap);
			}
		}
		repaint();
	}

	@Override
	public JComponent getComponent() {
		return this;
	}

	public void setLifeSet(TreeSet<Long> set) {
		service.setIndices(set);
		colorsByPixel = new Color[getOverviewPixelCount()];
		refreshUpdater.updateLater();
	}

	/**
	 * Causes this component to completely compute the colors used to paint the overview bar.
	 */
	public void refreshAll() {
		colorsByPixel = new Color[getOverviewPixelCount()];
		refreshUpdater.updateLater();
	}

	/**
	 * Returns the PluginTool
	 * 
	 * @return the PluginTool
	 */
	public PluginTool getTool() {
		return tool;
	}

	public void setPlugin(TimeOverviewColorPlugin plugin) {
		this.plugin = plugin;
		service.setPlugin(plugin);
	}

	public Lifespan getLifespan() {
		return service.getBounds();
	}
	
	public void setLifespan(Lifespan bounds) {
		service.setBounds(bounds);
	}

	@Override
	public void setProgram(Program program, AddressIndexMap map) {
		// Ignored	
	}

	@Override
	public void setNavigatable(Navigatable navigatable) {
		// Ignored
	}

}
