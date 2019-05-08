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
package ghidra.app.plugin.core.overview;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import docking.action.DockingActionIf;
import docking.help.Help;
import ghidra.app.services.GoToService;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.util.task.SwingUpdateManager;

/**
 * Overview bar component.  Uses color to indicate various address based properties for a program.
 * Uses an {@link OverviewColorService} to get the appropriate color for an address.
 */
public class OverviewColorComponent extends JPanel implements OverviewProvider {
	private static final Color DEFAULT_COLOR = Color.GRAY;
	private OverviewColorService service;
	private Color[] colors = new Color[0];
	private final SwingUpdateManager refreshUpdater =
		new SwingUpdateManager(100, 15000, () -> doRefresh());
	private AddressIndexMap map;
	private PluginTool tool;
	private List<DockingActionIf> actions;

	/**
	 * Constructor
	 *
	 * @param tool the PluginTool
	 * @param overviewColorService the {@link OverviewColorService} that provides colors for various
	 * addresses.
	 */
	public OverviewColorComponent(PluginTool tool, OverviewColorService overviewColorService) {
		this.tool = tool;
		this.service = overviewColorService;
		overviewColorService.setOverviewComponent(this);
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (e.getButton() == MouseEvent.BUTTON1) {
					Address address = getAddress(e.getY());
					gotoAddress(address);
				}
			}
		});
		ToolTipManager.sharedInstance().registerComponent(this);
		Help.getHelpService().registerHelp(this, service.getHelpLocation());
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

	protected void gotoAddress(Address address) {
		GoToService gotoService = tool.getService(GoToService.class);
		if (gotoService != null) {
			gotoService.goTo(address);
		}
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		Address address = getAddress(e.getY());
		return service.getToolTipText(address);
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		int width = getWidth();
		int pixelCount = getOverviewPixelCount();

		g.setColor(getBackground());
		g.fillRect(0, 0, width - 1, getHeight() - 1);

		if (service.getProgram() == null) {
			return;
		}

		for (int i = 0; i < pixelCount; i++) {
			Color color = getColor(i);
			g.setColor(color);
			g.fillRect(1, i, width - 3, 1);
		}
		if (colors.length != pixelCount) {
			colors = new Color[pixelCount];
			refreshUpdater.updateLater();
		}
	}

	private Color getColor(int index) {
		if (colors != null && index < colors.length) {
			return colors[index];
		}
		return DEFAULT_COLOR;
	}

	private int getOverviewPixelCount() {
		return Math.max(getHeight(), 0);
	}

	private void doRefresh() {
		if (map == null) {
			return;
		}
		BigInteger indexCount = map.getIndexCount();
		if (indexCount.equals(BigInteger.ZERO)) {
			Arrays.fill(colors, Color.GRAY);
			repaint();
			return;
		}

		BigInteger bigTotal = BigInteger.valueOf(colors.length);
		for (int i = 0; i < colors.length; i++) {
			if (colors[i] == null) {
				BigInteger index = indexCount.multiply(BigInteger.valueOf(i)).divide(bigTotal);
				Address address = map.getAddress(index);
				colors[i] = service.getColor(address);
			}
		}
		repaint();
	}

	private Address getAddress(int pixelIndex) {
		BigInteger bigHeight = BigInteger.valueOf(getOverviewPixelCount());
		BigInteger bigPixelIndex = BigInteger.valueOf(pixelIndex);
		BigInteger bigIndex = map.getIndexCount().multiply(bigPixelIndex).divide(bigHeight);
		return map.getAddress(bigIndex);
	}

	private int getPixelIndex(Address address) {
		BigInteger addressIndex = map.getIndex(address);
		if (addressIndex == null) {
			return -1;
		}
		BigInteger bigHeight = BigInteger.valueOf(getOverviewPixelCount());
		BigInteger indexCount = map.getIndexCount();
		return addressIndex.multiply(bigHeight).divide(indexCount).intValue();
	}

	@Override
	public JComponent getComponent() {
		return this;
	}

	@Override
	public void setAddressIndexMap(AddressIndexMap map) {
		this.map = map;
		colors = new Color[getOverviewPixelCount()];
		refreshUpdater.updateLater();
	}

	/**
	 * Causes this component to completely compute the colors used to paint the overview bar.
	 */
	public void refreshAll() {
		colors = new Color[getOverviewPixelCount()];
		refreshUpdater.updateLater();
	}

	/**
	 * Causes the component to refresh any colors for the given address range.
	 * @param start the start of the address range to refresh.
	 * @param end the end of the address range to refresh.
	 */
	public void refresh(Address start, Address end) {
		if (start == null) {
			return;
		}
		if (end == null) {
			end = start;
		}
		int pixelStart = getPixelIndex(start);
		int pixelEnd = getPixelIndex(end);
		for (int i = pixelStart; i <= pixelEnd; i++) {
			if (i >= 0 & i < colors.length) {
				colors[i] = null;
			}
		}
		refreshUpdater.updateLater();
	}

	/**
	 * Returns the PluginTool
	 * @return the PluginTool
	 */
	public PluginTool getTool() {
		return tool;
	}

}
