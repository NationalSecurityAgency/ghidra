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
package ghidra.app.util.viewer.format;

import java.awt.BorderLayout;
import java.awt.Point;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.action.DockingActionIf;
import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.actions.*;
import ghidra.util.HelpLocation;

/**
 * Class to manage the tabbed panel for field formats.
 */
public class FieldHeader extends JTabbedPane implements ChangeListener {

	private FormatManager formatManager;
	private FormatModelListener formatListener = new FormatModelListener() {
		@Override
		public void formatModelAdded(FieldFormatModel formatModel) {
			createTabs();
		}

		@Override
		public void formatModelRemoved(FieldFormatModel formatModel) {
			createTabs();
		}

		@Override
		public void formatModelChanged(FieldFormatModel formatModel) {
			repaint();
		}
	};

	private boolean tabLock = false;
	private FieldFactory selectedFactory;
	private List<FieldHeaderComp> fieldHeaderComps = new ArrayList<>();
	private IndexedScrollPane scroller;
	private JComponent centerComponent;
	private final FieldPanel fieldPanel;

	/**
	 * Constructs a new FieldHeaderPanel
	 * @param formatMgr the format manager to display tabbed panels for.
	 * @param scroller the scroll model to coordinate the view for.
	 * @param panel the field panel to use.
	 */
	public FieldHeader(FormatManager formatMgr, IndexedScrollPane scroller, FieldPanel panel) {
		this.formatManager = formatMgr;
		this.scroller = scroller;
		this.fieldPanel = panel;
		createTabs();

		formatMgr.addFormatModelListener(formatListener);
		HelpService help = Help.getHelpService();
		help.registerHelp(this, new HelpLocation("CodeBrowserPlugin", "Field_Formatter"));

		addChangeListener(this);
	}

	@Override
	public void stateChanged(ChangeEvent ev) {
		int index = this.getSelectedIndex();
		if (centerComponent == null || index < 0) {
			scroller.setColumnHeaderComp(null);
			return;
		}
		JPanel panel = (JPanel) getSelectedComponent();
		scroller.setColumnHeaderComp(fieldHeaderComps.get(index));
		panel.removeAll();
		panel.add(centerComponent, BorderLayout.CENTER);
		fieldPanel.requestFocus();
	}

	public List<DockingActionIf> getActions(String ownerName) {
		List<DockingActionIf> actionsList = new ArrayList<>();

		// field actions	    
		actionsList.add(new DisableFieldAction(ownerName, this));
		actionsList.add(new EnableFieldAction(ownerName, this));
		actionsList.add(new InsertRowAction(ownerName, this));
		actionsList.add(new RemoveFieldAction(ownerName, this));
		actionsList.add(new RemoveRowAction(ownerName, this));

		// format actions
		actionsList.add(new ResetFormatAction(ownerName, this));
		actionsList.add(new ResetAllFormatsAction(ownerName, formatManager, this));

		actionsList.add(new AddAllFieldAction(ownerName, this));
		actionsList.add(new RemoveAllFieldsAction(ownerName, this));
		actionsList.add(new AddSpacerFieldAction(ownerName, this));
		actionsList.add(new SetSpacerTextAction(ownerName));

		int numModels = formatManager.getNumModels();
		for (int i = 0; i < numModels; i++) {
			FieldFormatModel formatModel = formatManager.getModel(i);
			addLocalFieldActions(actionsList, ownerName, formatModel);
		}

		return new ArrayList<>(actionsList);
	}

	private void addLocalFieldActions(List<DockingActionIf> actionList, String ownerName,
			FieldFormatModel formatModel) {
		FieldFactory[] allFactories = formatModel.getAllFactories();

		for (FieldFactory fieldFactory : allFactories) {
			AddFieldAction addFieldAction =
				new AddFieldAction(ownerName, fieldFactory, this, formatModel);
			actionList.add(addFieldAction);
		}
	}

	private void createTabs() {
		fieldHeaderComps.clear();
		int selectedIndex = getSelectedIndex();
		removeAll();
		for (int i = 0; i < formatManager.getNumModels(); i++) {
			FieldFormatModel formatModel = formatManager.getModel(i);
			FieldHeaderComp fieldHeaderComp = new FieldHeaderComp(this, i);
			fieldHeaderComps.add(fieldHeaderComp);
			JPanel tabPanel = new JPanel(new BorderLayout());
			addTab(formatModel.getName(), tabPanel);
		}
		if (selectedIndex >= 0 && selectedIndex < getTabCount()) {
			setSelectedIndex(selectedIndex);
		}
	}

	/**
	 * Returns the currently tabbed model.
	 */
	public FieldFormatModel getCurrentModel() {
		return formatManager.getModel(getSelectedIndex());
	}

	/**
	 * Resets the currently tabbed model to its default format.
	 */
	public void resetFormat() {
		formatManager.setDefaultFormat(getSelectedIndex());
	}

	/**
	 * Sets the current tab to the given model.
	 * @param factory the format model to make the current tab.
	 */
	public void setSelectedFieldFactory(FieldFactory factory) {
		if (!tabLock) {
			setSelectedIndex(indexOfTab(factory.getFieldModel().getName()));
			selectedFactory = factory;
		}
	}

	public FieldFactory getSelectedFieldFactory() {
		return selectedFactory;
	}

	/**
	 * Resets all the format models to their default formats
	 */
	public void resetAllFormats() {
		formatManager.setDefaultFormats();
	}

	/**
	 * Returns the a FieldHeaderLocation for the given point within the header.
	 */
	public FieldHeaderLocation getFieldHeaderLocation(Point p) {
		return getHeaderTab().getFieldHeaderLocation(p);
	}

	/**
	 * Returns the field header tab component.
	 */
	public FieldHeaderComp getHeaderTab() {
		return fieldHeaderComps.get(getSelectedIndex());
	}

	/**
	 * Sets the tab lock so the tab won't reposition.
	 * @param b true to set the lock, false to release the lock.
	 */
	public void setTabLock(boolean b) {
		tabLock = b;
	}

	public FormatManager getFormatManager() {
		return formatManager;
	}

	public void setViewComponent(JComponent centerComponent) {
		this.centerComponent = centerComponent;
		stateChanged(null);
	}

//	/**
//	 * Main test.
//	 * @param args command line arguments.
//	 */
//	public static void main(String[] args) {
//		DockingApplication.initialize(new HeadedDockingApplicationConfiguration());
//		try {
//			ClassSearcher.setXmlRestoreFile(GenericRunInfo.getUserDataDirPath() +
//				File.separatorChar + "TestClasses.xml");
//			ClassSearcher.search(false, TaskMonitorAdapter.DUMMY_MONITOR);
//		}
//		catch (CancelledException e) {
//			// can't happen--dummy monitor
//		}
//
//		JFrame frame = new JFrame("Header");
//		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//		Container c = frame.getContentPane();
//		c.setLayout(new BorderLayout());
//		final FormatManager mgr = new FormatManager(new Options("display"), new Options("field"));
//		FieldHeader headerPanel = new FieldHeader(mgr, null, null);
//		JPanel panel = new JPanel() {
//			@Override
//			public Dimension getPreferredSize() {
//				return new Dimension(mgr.getMaxWidth(), 400);
//			}
//		};
//		JScrollPane jScrollPane = new JScrollPane(panel);
//		jScrollPane.getViewport().setScrollMode(JViewport.SIMPLE_SCROLL_MODE);
//		c.add(jScrollPane);
//		frame.setSize(600, 600);
//		frame.setVisible(true);
//
//	}

}
