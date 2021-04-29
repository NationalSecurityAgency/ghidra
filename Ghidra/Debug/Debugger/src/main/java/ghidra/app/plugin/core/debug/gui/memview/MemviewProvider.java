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
package ghidra.app.plugin.core.debug.gui.memview;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractRefreshAction;
import ghidra.app.plugin.core.debug.gui.memview.actions.*;
import ghidra.app.services.DebuggerListingService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

public class MemviewProvider extends ComponentProviderAdapter {

	private static final String TITLE = "Memview";

	private Wiring autoServiceWiring;
	@AutoServiceConsumed
	private DebuggerListingService listingService;

	private DebuggerMemviewPlugin plugin;
	private JComponent mainPanel;
	private MemviewPanel memviewPanel;
	private MemviewTable memviewTable;
	private JScrollPane scrollPane;

	//private Address location;
	private boolean vertical = true;
	private boolean applyFilter = true;

	private double zoomAmountA = 1.0;
	private double zoomAmountT = 1.0;
	long halfPage = 512L;

	public MemviewProvider(PluginTool tool, DebuggerMemviewPlugin plugin) {
		super(tool, TITLE, plugin.getName());
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		//setIcon(DebuggerResources.ICON_PROVIDER_REGIONS);
		//setHelpLocation(DebuggerResources.HELP_PROVIDER_REGIONS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		mainPanel = new JPanel(new BorderLayout());
		mainPanel.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				resized();
			}
		});
		tool.addComponentProvider(this, false);
		createActions();
		buildPanel();
	}

	private void createActions() {

		DockingAction zoomInAAction = new ZoomInAAction(this);
		tool.addLocalAction(this, zoomInAAction);

		DockingAction zoomOutAAction = new ZoomOutAAction(this);
		tool.addLocalAction(this, zoomOutAAction);

		DockingAction zoomInTAction = new ZoomInTAction(this);
		tool.addLocalAction(this, zoomInTAction);

		DockingAction zoomOutTAction = new ZoomOutTAction(this);
		tool.addLocalAction(this, zoomOutTAction);

		new ToggleActionBuilder("Toggle Layout", plugin.getName()) //
				//.menuPath("&Toggle layout") //
				.toolBarIcon(AbstractRefreshAction.ICON)
				.helpLocation(new HelpLocation(plugin.getName(), "toggle_layout")) //
				.onAction(ctx -> performToggleLayout(ctx))
				.buildAndInstallLocal(this);

		new ToggleActionBuilder("Toggle Process Trace", plugin.getName()) //
				//.menuPath("&Toggle layout") //
				.toolBarIcon(DebuggerResources.ICON_SYNC)
				.helpLocation(new HelpLocation(plugin.getName(), "toggle_process_trace")) //
				.onAction(ctx -> performToggleTrace(ctx))
				.selected(false)
				.buildAndInstallLocal(this);

		new ToggleActionBuilder("Apply Filter To Panel", plugin.getName()) //
				//.menuPath("&Toggle layout") //
				.toolBarIcon(DebuggerResources.ICON_FILTER)
				.helpLocation(new HelpLocation(plugin.getName(), "apply_to_panel")) //
				.onAction(ctx -> performApplyFilterToPanel(ctx))
				.selected(true)
				.buildAndInstallLocal(this);

	}

	void buildPanel() {
		mainPanel.removeAll();
		memviewPanel = new MemviewPanel(this);
		memviewTable = new MemviewTable(this);

		scrollPane = new JScrollPane(memviewPanel);
		scrollPane.setPreferredSize(memviewPanel.getSize());

		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setRightComponent(scrollPane);
		splitPane.setLeftComponent(memviewTable.getComponent());
		splitPane.setDividerLocation(0.5);
		mainPanel.add(splitPane, BorderLayout.CENTER);
		//mainPanel.add(memviewTable.getComponent(), BorderLayout.WEST);

		setDirection();

		mainPanel.validate();
	}

	private void performToggleLayout(ActionContext ctx) {
		vertical = !vertical;
		setDirection();
		refresh();
	}

	private void performToggleTrace(ActionContext ctx) {
		plugin.toggleTrackTrace();
	}

	private void performApplyFilterToPanel(ActionContext ctx) {
		applyFilter = !isApplyFilter();
		applyFilter();
	}

	public void applyFilter() {
		if (applyFilter) {
			memviewTable.applyFilter();
		}
		else {
			memviewPanel.setBoxes(memviewTable.getBoxes());
		}
		refresh();
	}

	private void setDirection() {
		memviewPanel.setVerticalMode(vertical);
	}

	void dispose() {
		tool.removeComponentProvider(this);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null && event.getSource() == mainPanel) {
			return new ActionContext(this, mainPanel);
		}
		if (event != null && event.getSource() == memviewPanel) {
			return new ActionContext(this, memviewPanel);
		}
		return null;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), plugin.getName());
	}

	public void setProgram(Program program) {
		memviewTable.setProgram(program);
	}

	public void initViews() {
		memviewPanel.initViews();
		memviewPanel.setPreferredSize(new Dimension(300, 100));
		memviewTable.setListingService(listingService);
		mainPanel.doLayout();
		mainPanel.repaint();
	}

	public void refresh() {
		String subTitle = " (" + zoomAmountA + "x:" + zoomAmountT + ") ";
		subTitle += memviewPanel.getTitleAnnotation();
		setSubTitle(subTitle);
		memviewPanel.refresh();
		scrollPane.getViewport().doLayout();
	}

	public void goTo(int x, int y) {
		Rectangle bounds = scrollPane.getBounds();
		scrollPane.getViewport()
				.scrollRectToVisible(new Rectangle(x, y, bounds.width, bounds.height));
		scrollPane.getViewport().doLayout();
	}

	public void goTo(MemoryBox box) {
		Point p = new Point(box.getX(vertical) - 10, box.getY(vertical) - 10);
		Point p0 = scrollPane.getViewport().getViewPosition();
		int w = scrollPane.getViewport().getWidth();
		int h = scrollPane.getViewport().getHeight();
		if (p.x > p0.x && p.x < p0.x + w && p.y > p0.y && p.y < p0.y + h) {
			return;
		}
		scrollPane.getViewport().setViewPosition(p);
	}

	public void selectTableEntry(Set<MemoryBox> boxes) {
		memviewTable.setSelection(boxes);
	}

	public void selectPanelPosition(Set<MemoryBox> boxes) {
		memviewPanel.setSelection(boxes);
		if (boxes.size() == 1) {
			Iterator<MemoryBox> iterator = boxes.iterator();
			goTo(iterator.next());
		}
	}

	public void changeZoomA(int changeAmount) {
		this.zoomAmountA = (float) (zoomAmountA * Math.pow(2.0, changeAmount));
		memviewPanel.scaleCurrentPixelAddr(changeAmount);
	}

	public double getZoomAmountA() {
		return zoomAmountA;
	}

	public void changeZoomT(int changeAmount) {
		this.zoomAmountT = (float) (zoomAmountT * Math.pow(2.0, changeAmount));
		memviewPanel.scaleCurrentPixelTime(changeAmount);
	}

	public double getZoomAmountT() {
		return zoomAmountT;
	}

	void resized() {
		memviewPanel.refresh();
	}

	public void setBoxes(List<MemoryBox> blist) {
		Swing.runIfSwingOrRunLater(() -> {
			memviewTable.setBoxes(blist);
			memviewTable.applyFilter();
			//memviewPanel.setBoxes(memviewTable.getBoxes());
		});
	}

	public void setBoxesInPanel(List<MemoryBox> blist) {
		Swing.runIfSwingOrRunLater(() -> {
			memviewPanel.setBoxes(blist);
			memviewPanel.refresh();
		});
	}

	public void addBox(MemoryBox box) {
		List<MemoryBox> blist = new ArrayList<>();
		blist.add(box);
		addBoxes(blist);
	}

	public void addBoxes(List<MemoryBox> blist) {
		Swing.runIfSwingOrRunLater(() -> {
			memviewTable.addBoxes(blist);
			memviewTable.applyFilter();
			//memviewPanel.addBoxes(memviewTable.getBoxes());
		});
	}

	public boolean isApplyFilter() {
		return applyFilter;
	}

	public void reset() {
		Swing.runIfSwingOrRunLater(() -> {
			memviewTable.reset();
			memviewPanel.reset();
		});
	}
}
