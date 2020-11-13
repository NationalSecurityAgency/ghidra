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
package ghidra.app.merge.tool;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.EmptyBorderButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.fieldpanel.support.BackgroundColorModel;
import ghidra.app.merge.MergeConstants;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.codebrowser.hover.*;
import ghidra.app.services.*;
import ghidra.app.util.viewer.field.RegisterFieldFactory;
import ghidra.app.util.viewer.format.FieldHeaderComp;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.listingpanel.*;
import ghidra.app.util.viewer.multilisting.AddressTranslator;
import ghidra.app.util.viewer.multilisting.MultiListingLayoutModel;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.app.util.viewer.util.TitledPanel;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProviderDecorator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class ListingMergePanel extends JPanel
		implements MergeConstants, FocusListener, CodeFormatService {
	private static Icon hideIcon = ResourceManager.loadImage("images/collapse.gif");
	private static Icon showIcon = ResourceManager.loadImage("images/expand.gif");

	private JComponent topComp;
	private JComponent bottomComp;
	protected TitledPanel[] titlePanels;
	private ListingPanel[] listingPanels;
	private FieldPanelCoordinator coordinator;
	private FormatManager formatMgr;
	private MultiListingLayoutModel multiModel;
	private Program[] programs = new Program[4];
	private int currProgIndex = 0;
	private MergeColorBackgroundModel backgroundColorModel = new MergeColorBackgroundModel();
	private ChangeListener backgroundChangeListener = e -> {
		for (int i = 0; i < 4; i++) {
			listingPanels[i].getFieldPanel().repaint();
		}
	};
	private AddressIndexMap addressIndexMap;
	private PluginTool tool;
	private boolean showListings;

	private ReferenceListingHover referenceHoverService;
	private DataTypeListingHover dataTypeHoverService;
	private TruncatedTextListingHover truncatedTextHoverService;
	private FunctionNameListingHover functionNameHoverService;

	public ListingMergePanel(PluginTool tool, Program original, Program result, Program myChanges,
			Program latest, boolean showListings) {
		super(new BorderLayout());
		this.tool = tool;
		this.showListings = showListings;

		listingPanels = new ListingPanel[4];
		titlePanels = new TitledPanel[4];
		programs[ORIGINAL] = original;
		programs[RESULT] = result;
		programs[MY] = myChanges;
		programs[LATEST] = latest;
		formatMgr = new FormatManager(getDisplayOptions(), getFieldOptions());
		multiModel = new MultiListingLayoutModel(formatMgr, programs, programs[0].getMemory());
		buildPanel();
		addressIndexMap = listingPanels[0].getAddressIndexMap();

		ServiceProviderDecorator sp = ServiceProviderDecorator.createEmptyDecorator();
		sp.overrideService(GoToService.class, new MyGoToService());
		formatMgr.setServiceProvider(sp);

		FieldPanel[] fieldPanels = new FieldPanel[4];
		for (int i = 0; i < 4; i++) {
			fieldPanels[i] = listingPanels[i].getFieldPanel();
			fieldPanels[i].addFocusListener(this);
			fieldPanels[i].setBackgroundColorModel(backgroundColorModel);
			//			fieldPanels[i].setCursorOn(false);
			LockComponent lock = new LockComponent();
			titlePanels[i].addTitleComponent(lock);
			lock.addActionListener(new LockListener(listingPanels[i]));

		}

		backgroundColorModel.addChangeListener(backgroundChangeListener);
		coordinator = new FieldPanelCoordinator(fieldPanels);

		titlePanels[RESULT].addTitleComponent(new ShowHeaderButton());

		initializeListingHoverService();
	}

	private void initializeListingHoverService() {

		// The CodeFormatService is needed by the ReferenceHover.
		referenceHoverService = new ReferenceListingHover(tool, this);
		dataTypeHoverService = new DataTypeListingHover(tool);
		truncatedTextHoverService = new TruncatedTextListingHover(tool);
		functionNameHoverService = new FunctionNameListingHover(tool);

		initializeListingHoverService(listingPanels[RESULT]);
		initializeListingHoverService(listingPanels[LATEST]);
		initializeListingHoverService(listingPanels[MY]);
		initializeListingHoverService(listingPanels[ORIGINAL]);
	}

	private void initializeListingHoverService(ListingPanel listingPanel) {
		listingPanel.addHoverService(referenceHoverService);
		listingPanel.addHoverService(dataTypeHoverService);
		listingPanel.addHoverService(truncatedTextHoverService);
		listingPanel.addHoverService(functionNameHoverService);
		listingPanel.setHoverMode(true);
	}

	private ToolOptions getFieldOptions() {
		ToolOptions fieldOptions = new ToolOptions("field");
		fieldOptions.setBoolean(RegisterFieldFactory.DISPLAY_HIDDEN_REGISTERS_OPTION_NAME, true);
		return fieldOptions;
	}

	private ToolOptions getDisplayOptions() {
		return new ToolOptions("display");
	}

	private void buildPanel() {

		if (showListings) {
			listingPanels[RESULT] = new ListingPanel(formatMgr, multiModel.getAlignedModel(0));
			listingPanels[LATEST] = new ListingPanel(formatMgr, multiModel.getAlignedModel(1));
			listingPanels[MY] = new ListingPanel(formatMgr, multiModel.getAlignedModel(2));
			listingPanels[ORIGINAL] = new ListingPanel(formatMgr, multiModel.getAlignedModel(3));
		}
		else {
			ListingModel model = new EmptyListingModel();
			listingPanels[RESULT] = new ListingPanel(formatMgr, model);
			listingPanels[LATEST] = new ListingPanel(formatMgr, model);
			listingPanels[MY] = new ListingPanel(formatMgr, model);
			listingPanels[ORIGINAL] = new ListingPanel(formatMgr, model);
		}

		titlePanels[RESULT] = new TitledPanel(RESULT_TITLE, listingPanels[RESULT], 5);
		titlePanels[LATEST] = new TitledPanel(LATEST_TITLE, listingPanels[LATEST], 5);
		titlePanels[MY] = new TitledPanel(MY_TITLE, listingPanels[MY], 5);
		titlePanels[ORIGINAL] = new TitledPanel(ORIGINAL_TITLE, listingPanels[ORIGINAL], 5);

		JSplitPane splitPane =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, titlePanels[LATEST], titlePanels[MY]);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		splitPane =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, splitPane, titlePanels[ORIGINAL]);
		splitPane.setResizeWeight(0.6666);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, true, titlePanels[RESULT], splitPane);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		add(splitPane, BorderLayout.CENTER);
	}

	public void setTopComponent(final JComponent comp) {
		SystemUtilities.runSwingNow(() -> doSetTopComponent(comp));
	}

	private void doSetTopComponent(JComponent comp) {
		if (topComp == comp) {
			return;
		}
		if (topComp != null) {
			remove(topComp);
		}
		topComp = comp;
		if (topComp != null) {
			add(topComp, BorderLayout.NORTH);
		}

		invalidate();
		repaint();
	}

	public void setBottomComponent(final JComponent comp) {
		SystemUtilities.runSwingNow(() -> doSetBottomComponent(comp));
	}

	private void doSetBottomComponent(JComponent comp) {
		if (bottomComp == comp) {
			return;
		}
		if (bottomComp != null) {
			remove(bottomComp);
		}

		invalidate();
		repaint(); // Since we are removing this while the panel is on the screen.

		bottomComp = comp;
		if (bottomComp != null) {
			add(bottomComp, BorderLayout.SOUTH);
		}
		invalidate();
		repaint();
	}

	public Program getFocusedProgram() {
		return programs[currProgIndex];
	}

	public ListingPanel getFocusedListingPanel() {
		return listingPanels[currProgIndex];
	}

	public ListingPanel getResultPanel() {
		return listingPanels[RESULT];
	}

	public void goTo(Address addr) {
		Memory memory = programs[currProgIndex].getMemory();
		listingPanels[currProgIndex].setView(memory);
		listingPanels[currProgIndex].goTo(addr);
	}

	public void goTo(Address addr, int programIndex) {
		if (addr == null) {
			// clear the listing
			listingPanels[programIndex].setView(new AddressSet());
		}
		else if (addr.isExternalAddress()) {
			// Change the view to include only the external address.
			AddressSet newView = new AddressSet(addr, addr);
			AddressSetView oldView = listingPanels[programIndex].getView();
			if (!newView.equals(oldView)) {
				listingPanels[programIndex].setView(newView);
			}
		}
		else {
			// Is there a better way to make sure we have the entire memory in the view?
			Memory memory = programs[programIndex].getMemory();
			AddressSetView currentView = listingPanels[programIndex].getView();
			if (currentView.equals(memory)) {
				listingPanels[programIndex].setView(memory);
			}

			listingPanels[programIndex].goTo(addr);
		}
		listingPanels[programIndex].validate();
	}

	public void goTo(ProgramLocation loc, boolean centerOnScreen) {
		listingPanels[currProgIndex].goTo(loc, centerOnScreen);
	}

	public void setViewToProgram(int programIndex) {
		Memory memory = programs[programIndex].getMemory();
		listingPanels[programIndex].setView(memory);
	}

	public void emptyViewForProgram(int programIndex) {
		AddressSet emptySet = new AddressSet();
		listingPanels[programIndex].setView(emptySet);
	}

	/**
	 * Color the background of all 4 listings to the indicated color for 
	 * the indicated addresses.
	 * @param addrSet
	 */
	public void paintAllBackgrounds(AddressSetView addrSet) {
		backgroundColorModel.setAddressSet(addrSet);
	}

	/**
	 * Color the background of all 4 listings to the default color for all addresses.
	 */
	public void clearAllBackgrounds() {
		backgroundColorModel.setAddressSet(null);
	}

	public void dispose() {
		backgroundColorModel.removeChangeListener(backgroundChangeListener);
		for (int i = 0; i < 4; i++) {
			listingPanels[i].dispose();
		}
	}

	/**
	 * @see java.awt.event.FocusListener#focusGained(java.awt.event.FocusEvent)
	 */
	@Override
	public void focusGained(FocusEvent e) {
		Component comp = e.getComponent();
		for (int i = 0; i < 4; i++) {
			if (listingPanels[i].getFieldPanel() == comp) {
				currProgIndex = i;
			}
		}
	}

	/**
	 * @see java.awt.event.FocusListener#focusLost(java.awt.event.FocusEvent)
	 */
	@Override
	public void focusLost(FocusEvent e) {
		// don't care
	}

	public Object getActionContext(MouseEvent event) {
		ListingPanel panel = null;
		if (event != null) {
			Component c = (Component) event.getSource();
			if (c instanceof FieldHeaderComp) {
				return listingPanels[0].getFieldHeader().getFieldHeaderLocation(event.getPoint());
			}
			for (int i = 0; i < 4; i++) {
				if (listingPanels[i].getFieldPanel() == c) {
					panel = listingPanels[i];
					break;
				}
			}
		}
		if (panel == null) {
			panel = listingPanels[currProgIndex];
		}
		if (panel != null) {
			return panel.getProgramLocation();
		}
		return null;
	}

	/**
	 * Adds a button press listener.
	 * @param listener the listener to add.
	 */
	public void addButtonPressedListener(ButtonPressedListener listener) {
		for (ListingPanel listingPanel : listingPanels) {
			listingPanel.addButtonPressedListener(listener);
		}
	}

	/**
	 * Get the indicated program version.
	 * @param version LATEST, CHECKED_OUT, ORIGINAL, RESULT from MergeConstants
	 * @return the program
	 */
	public Program getProgram(int version) {
		return programs[version];
	}

	/**
	 * Add the result program's listing model as a listener to the result program 
	 * for domain object events.
	 */
	public void addDomainObjectListener() {
		DomainObjectListener listingModel = (DomainObjectListener) multiModel.getModel(RESULT);
		programs[RESULT].addListener(listingModel);
	}

	/**
	 * Remove the result program's listing model as a listener to the result program 
	 * for domain object events.
	 */
	public void removeDomainObjectListener() {
		DomainObjectListener listingModel = (DomainObjectListener) multiModel.getModel(RESULT);
		programs[RESULT].removeListener(listingModel);
	}

	public void setAddressTranslator(AddressTranslator translator) {
		multiModel.setAddressTranslator(translator);
	}

	@Override
	public FormatManager getFormatManager() {
		return formatMgr;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class MyGoToService implements GoToService {
		@Override
		public boolean goTo(Address gotoAddress) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(gotoAddress);
		}

		@Override
		public boolean goTo(Address gotoAddress, Program program) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(gotoAddress);
		}

		public boolean goTo(long offset) {
			throw new NotYetImplementedException();
		}

		@Override
		public boolean goTo(ProgramLocation loc) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(loc);
		}

		@Override
		public boolean goTo(ProgramLocation loc, Program program) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(loc);
		}

		@Override
		public boolean goTo(Navigatable navigatable, ProgramLocation loc, Program program) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(loc);
		}

		@Override
		public boolean goTo(Address currentAddress, Address gotoAddress) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(currentAddress, gotoAddress);
		}

		@Override
		public boolean goToQuery(Address fromAddr, QueryData queryData,
				GoToServiceListener listener, TaskMonitor monitor) {
			throw new NotYetImplementedException();
		}

		@Override
		public boolean goToQuery(Navigatable nav, Address fromAddr, QueryData queryData,
				GoToServiceListener listener, TaskMonitor monitor) {
			throw new NotYetImplementedException();
		}

		@Override
		public boolean goTo(Navigatable navigatable, Address goToAddress) {
			throw new NotYetImplementedException();
		}

		@Override
		public boolean goToExternalLocation(ExternalLocation extLoc,
				boolean checkNavigationOption) {
			return false;
		}

		@Override
		public boolean goToExternalLocation(Navigatable navigatable, ExternalLocation externalLoc,
				boolean checkNavigationOption) {
			return false;
		}

		@Override
		public GoToOverrideService getOverrideService() {
			return null;
		}

		@Override
		public void setOverrideService(GoToOverrideService override) {
			// no-op
		}

		@Override
		public Navigatable getDefaultNavigatable() {
			return null;
		}

		@Override
		public boolean goTo(Navigatable navigatable, Program program, Address address,
				Address refAddress) {
			ListingPanel lp = getFocusedListingPanel();
			return lp.goTo(address);

		}
	}

	private class ShowHeaderButton extends EmptyBorderButton {
		ShowHeaderButton() {
			super(showIcon);
			setFocusable(false);
			setToolTipText("Toggle Format Header");
			addActionListener(e -> {
				if (isSelected()) {
					setSelected(false);
					setIcon(showIcon);
					listingPanels[RESULT].showHeader(false);
				}
				else {
					setSelected(true);
					setIcon(hideIcon);
					listingPanels[RESULT].showHeader(true);
				}
			});
		}
	}

	private class LockListener implements ActionListener {
		ListingPanel panel;

		LockListener(ListingPanel panel) {
			this.panel = panel;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			LockComponent lock = (LockComponent) e.getSource();
			if (lock.isLocked()) {
				coordinator.add(panel.getFieldPanel());
			}
			else {
				coordinator.remove(panel.getFieldPanel());
			}
		}
	}

	private class MergeColorBackgroundModel implements BackgroundColorModel {
		private Color defaultBackgroundColor;
		private AddressSetView addressSet;
		private WeakSet<ChangeListener> backgroundListenerList =
			WeakDataStructureFactory.createCopyOnReadWeakSet();

		private void addChangeListener(ChangeListener listener) {
			backgroundListenerList.add(listener);
		}

		private void removeChangeListener(ChangeListener listener) {
			backgroundListenerList.remove(listener);
		}

		@Override
		public Color getBackgroundColor(BigInteger index) {
			if (addressSet == null) {
				return defaultBackgroundColor;
			}

			Address address = addressIndexMap.getAddress(index);
			if (addressSet.contains(address)) {
				return MergeConstants.HIGHLIGHT_COLOR;
			}
			return defaultBackgroundColor;
		}

		@Override
		public Color getDefaultBackgroundColor() {
			return defaultBackgroundColor;
		}

		@Override
		public void setDefaultBackgroundColor(Color c) {
			defaultBackgroundColor = c;
			notifyListeners();
		}

		public void setAddressSet(AddressSetView addressSet) {
			this.addressSet = addressSet;
			notifyListeners();
		}

		public void notifyListeners() {
			ChangeEvent event = new ChangeEvent(this);
			for (ChangeListener backgroundListener : backgroundListenerList) {
				backgroundListener.stateChanged(event);
			}
		}
	}

	public String getVersionName(Program program) {
		if (program == programs[RESULT]) {
			return RESULT_TITLE;
		}
		if (program == programs[LATEST]) {
			return LATEST_TITLE;
		}
		if (program == programs[MY]) {
			return MY_TITLE;
		}
		if (program == programs[ORIGINAL]) {
			return ORIGINAL_TITLE;
		}
		return "Unknown";
	}

}

class LockComponent extends GCheckBox {
	private static final Icon lock = ResourceManager.loadImage("images/lock.gif");
	private static final Icon unlock = ResourceManager.loadImage("images/unlock.gif");

	LockComponent() {
		super(unlock);
		setToolTipText("Lock/Unlock with other views");
		setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 0));
		setSelectedIcon(lock);
		setSelected(true);
	}

	boolean isLocked() {
		return isSelected();
	}

	void setLocked(boolean lock) {
		setSelected(lock);
	}
}
/***
// class LockComponent extends ToolbarButton {
//	private static final Icon lock = ResourceManager.loadImage("images/lock.gif");
//	private static final Icon unlock = ResourceManager.loadImage("images/unlock.gif");
//	LockComponent() {
//		super(unlock);
//		setBorder(BorderFactory.createEmptyBorder(0,2,0,2));
//		setSelectedIcon(lock);		
//		setSelected(true);
//		addActionListener(new ActionListener() {
//			public void actionPerformed(ActionEvent e) {
//				setSelected(!isSelected());
//			}
//		});
//	}
//	boolean isLocked() {
//		return isSelected();
//	}
//	void setLocked(boolean lock) {
//		setSelected(lock);
//	}
// }
 ***/
