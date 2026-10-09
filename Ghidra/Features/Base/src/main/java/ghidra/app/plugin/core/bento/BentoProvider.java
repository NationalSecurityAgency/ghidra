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
package ghidra.app.plugin.core.bento;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingAction;
import docking.action.builder.ToggleActionBuilder;
import generic.theme.GIcon;
import ghidra.app.plugin.core.bento.actions.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import resources.ResourceManager;

public class BentoProvider extends ComponentProviderAdapter {

	private BentoServicePlugin plugin;

	private JComponent mainPanel;
	private BentoPanel bentoPanel;
	private BentoTable bentoTable;
	private JScrollPane scrollPane;

	private boolean applyFilter = true;

	private static final Icon ICON_REFRESH =
		ResourceManager.getScaledIcon(new GIcon("icon.debugger.refresh"), 12, 12);
	private static final Icon ICON_FILTER =
		ResourceManager.getScaledIcon(new GIcon("icon.widget.filterpanel.filter.off"), 12, 12);
	long halfPage = 512L;

	private Map<Integer, BentoRadix> radixMap = new HashMap<>();

	public BentoProvider(PluginTool tool, BentoServicePlugin plugin, boolean isTransient) {
		super(tool, plugin.title, plugin.getName());
		this.plugin = plugin;
		if (isTransient) {
			setTransient();
		}

		mainPanel = new JPanel(new BorderLayout());
		tool.addComponentProvider(this, false);
		createActions();
		buildPanel();
		mainPanel.addComponentListener(new ComponentAdapter() {
			private int lastWidth = -1;
			private int lastHeight = -1;

			@Override
			public void componentResized(ComponentEvent e) {
				int currentWidth = mainPanel.getWidth();
				int currentHeight = mainPanel.getHeight();
				if (currentWidth != lastWidth || currentHeight != lastHeight) {
					lastWidth = currentWidth;
					lastHeight = currentHeight;
					resized();
				}
			}
		});
	}

	protected void createActions() {

		DockingAction zoomInYAction = new ZoomInYAction(this);
		tool.addLocalAction(this, zoomInYAction);

		DockingAction zoomOutYAction = new ZoomOutYAction(this);
		tool.addLocalAction(this, zoomOutYAction);

		DockingAction zoomInXAction = new ZoomInXAction(this);
		tool.addLocalAction(this, zoomInXAction);

		DockingAction zoomOutXAction = new ZoomOutXAction(this);
		tool.addLocalAction(this, zoomOutXAction);

		new ToggleActionBuilder("Toggle Layout", getOwner())
				.toolBarIcon(ICON_REFRESH)
				.helpLocation(new HelpLocation(getOwner(), "toggle_layout"))
				.onAction(ctx -> performToggleLayout(ctx))
				.buildAndInstallLocal(this);

		new ToggleActionBuilder("Apply Filter To Panel", getOwner())
				.toolBarIcon(ICON_FILTER)
				.helpLocation(new HelpLocation(getOwner(), "apply_to_panel"))
				.onAction(ctx -> performApplyFilterToPanel(ctx))
				.selected(true)
				.buildAndInstallLocal(this);

	}

	void buildPanel() {
		mainPanel.removeAll();
		bentoPanel = new BentoPanel(this);
		bentoTable = new BentoTable(this);

		scrollPane = new JScrollPane(bentoPanel);
		scrollPane.setPreferredSize(bentoPanel.getSize());

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setRightComponent(scrollPane);
		splitPane.setLeftComponent(bentoTable.getComponent());

		splitPane.setResizeWeight(0.5);
		mainPanel.add(splitPane, BorderLayout.CENTER);

		initViews();
		mainPanel.validate();
	}

	private void performToggleLayout(ActionContext ctx) {
		toggleDirection();
		refresh();
	}

	protected void performToggleTracking(ActionContext ctx) {
		if (plugin != null) {
			plugin.toggleTracking();
		}
	}

	private void performApplyFilterToPanel(ActionContext ctx) {
		applyFilter = !isApplyFilter();
		applyFilter();
	}

	public void applyFilter() {
		if (applyFilter) {
			bentoTable.applyFilter();
		}
		else {
			bentoPanel.setBoxes(bentoTable.getBoxes());
		}
		refresh();
	}

	public void setIndex(boolean x, int index) {
		bentoTable.getModel().setIndex(x, index);
		bentoPanel.setIndex(x, index);
		refresh();
	}

	private void toggleDirection() {
		int xIndex = bentoPanel.getIndex(true);
		int yIndex = bentoPanel.getIndex(false);
		setIndex(true, yIndex);
		setIndex(false, xIndex);
		bentoPanel.setBoxes(bentoPanel.getBoxes());
	}

	void dispose() {
		tool.removeComponentProvider(this);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null && event.getSource() == mainPanel) {
			return new DefaultActionContext(this, mainPanel);
		}
		if (event != null && event.getSource() == bentoPanel) {
			return new DefaultActionContext(this, bentoPanel);
		}
		return null;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(getOwner(), getOwner());
	}

	public void setProgram(Program program) {
		bentoTable.setProgram(program);
	}

	public void initViews() {
		bentoPanel.initViews();
		bentoPanel.setPreferredSize(new Dimension(300, 100));
		bentoTable.setCodeViewerService(plugin.getCodeViewerService());
		mainPanel.doLayout();
		mainPanel.repaint();
	}

	public void refresh() {
		StringBuilder titleBuilder = new StringBuilder(bentoTable.getTitle());
		titleBuilder.append(" (")
				.append(bentoPanel.getZoom(0))
				.append(" \u00d7 ")
				.append(bentoPanel.getZoom(1))
				.append(") ")
				.append(bentoPanel.getTitleAnnotation());

		setSubTitle(titleBuilder.toString());
		bentoPanel.refresh();
		scrollPane.getViewport().doLayout();
	}

	public void goTo(int x, int y) {
		Rectangle bounds = scrollPane.getBounds();
		scrollPane.getViewport()
				.scrollRectToVisible(new Rectangle(x, y, bounds.width, bounds.height));
		scrollPane.getViewport().doLayout();
	}

	public void goTo(BentoBox box) {
		try {
			Point p = new Point(box.getPixelStart(bentoPanel.getIndex(true)) - 10,
				box.getPixelStart(bentoPanel.getIndex(false)) - 10);
			Point p0 = scrollPane.getViewport().getViewPosition();
			int w = scrollPane.getViewport().getWidth();
			int h = scrollPane.getViewport().getHeight();
			if (p.x > p0.x && p.x < p0.x + w && p.y > p0.y && p.y < p0.y + h) {
				return;
			}
			scrollPane.getViewport().setViewPosition(p);
		}
		catch (IndexOutOfBoundsException e) {
			// IGNORE
		}
	}

	public void selectTableEntry(Set<BentoBox> boxes) {
		bentoTable.setSelection(boxes);
	}

	public void selectPanelPosition(Set<BentoBox> boxes) {
		bentoPanel.setSelection(boxes);
		if (boxes.size() == 1) {
			Iterator<BentoBox> iterator = boxes.iterator();
			goTo(iterator.next());
		}
	}

	public double getZoomAmount(int index) {
		return bentoPanel.getZoom(index);
	}

	public void changeZoom(int index, int changeAmount) {
		bentoPanel.scaleCurrentPixel(index, changeAmount);
	}

	void resized() {
		bentoPanel.refresh();
	}

	public void setBoxes(List<BentoBox> blist) {
		if (!blist.isEmpty()) {
			BentoBox sample = blist.get(0);
			for (int i = 0; i < sample.getNumIndices(); i++) {
				BoundedObject bo = sample.getObj(i);
				radixMap.put(i, bo.getDefaultRadix());
			}
		}
		Swing.runIfSwingOrRunLater(() -> {
			bentoTable.setBoxes(blist);
			bentoTable.applyFilter();
		});
	}

	public void setBoxesInPanel(List<BentoBox> blist) {
		Swing.runIfSwingOrRunLater(() -> {
			bentoPanel.setBoxes(blist);
			bentoPanel.refresh();
		});
	}

	public void addBox(BentoBox box) {
		List<BentoBox> blist = new ArrayList<>();
		blist.add(box);
		addBoxes(blist);
	}

	public void addBoxes(List<BentoBox> blist) {
		Swing.runIfSwingOrRunLater(() -> {
			bentoTable.addBoxes(blist);
			bentoTable.applyFilter();
		});
	}

	public boolean isApplyFilter() {
		return applyFilter;
	}

	public void reset() {
		Swing.runIfSwingOrRunLater(() -> {
			bentoTable.reset();
			bentoPanel.reset();
		});
	}

	public void fireTableDataChanged() {
		Swing.runIfSwingOrRunLater(() -> {
			bentoTable.fireTableDataChanged();
		});
	}

	public void navigateToSelectedObject() {
		bentoTable.navigateToSelectedObject();
	}

	public void setColumns(List<String> cols) {
		bentoTable.setColumns(cols, bentoPanel);
	}

	protected BentoPanel getPanel() {
		return bentoPanel;
	}

	public void setRadix(int index, BentoRadix radix) {
		radixMap.put(index, radix);
	}

	public BentoRadix getRadix(int index) {
		BentoRadix radix = radixMap.get(index);
		return radix == null ? BentoRadix.DEFAULT : radix;
	}

}
