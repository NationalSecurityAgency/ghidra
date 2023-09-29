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
package ghidra.framework.main;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.table.*;
import ghidra.framework.main.datatree.VersionHistoryPanel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * Dialog to open a file that is versioned and allow a version to be
 * opened.
 * @param <T> domain object class
 */
public class OpenVersionedFileDialog<T extends DomainObject> extends DataTreeDialog {
	private static final String SHOW_HISTORY_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.SHOW_HISTORY";
	private static final String HEIGHT_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.HEIGHT";
	private static final String WIDTH_NO_HISTORY_PREFERENCES_KEY =
		"OPEN_PROGRAM_DIALOG.WIDTH_NO_HISTORY";
	private static final String WIDTH_WITH_HISTORY_PREFERENCES_KEY =
		"OPEN_PROGRAM_DIALOG.WIDTH_WITH_HISTORY";

	private final static int DEFAULT_WIDTH_NO_HISTORY = WIDTH;
	private final static int DEFAULT_WIDTH_WITH_HISTORY = 800;
	private final static int DIVIDER_SIZE = 2;

	private final static int PROJECT_FILES_TAB = 0;
	private final static int OPEN_OBJECT_LIST_TAB = 1;

	private JTabbedPane tabbedPane; // null if openDomainObjects not specified
	private JSplitPane splitPane;
	private JButton historyButton;
	private JPanel mainPanel;
	private boolean historyIsShowing;
	private PluginTool tool;

	private VersionHistoryPanel historyPanel;
	private List<DockingActionIf> popupActions = Collections.emptyList();

	private Class<T> domainObjectClass;
	private List<T> openDomainObjects; // list of allowed domain object which are already open
	private GFilterTable<T> openObjectsTable;

	/**
	 * Constructor
	 * @param tool tool where the file is being opened.
	 * @param title title to use
	 * @param domainObjectClass allowed domain object class which corresponds to {@code <T>}
	 */
	public OpenVersionedFileDialog(PluginTool tool, String title, Class<T> domainObjectClass) {
		super(tool.getToolFrame(), title, DataTreeDialog.OPEN, f -> {
			return domainObjectClass.isAssignableFrom(f.getDomainObjectClass());
		});
		this.tool = tool;
		this.domainObjectClass = domainObjectClass;
		init();
	}

	/**
	 * Set an optional list of already open domain objects of type {@code <T>} which may be
	 * selected instead of a project domain file.  The {@link #getDomainObject(Object, boolean)}
	 * method should be used when this optional list has been set.  If this dialog is reused
	 * the list should be set null if previously set.  This method must be invoked prior to 
	 * showing the dialog.
	 * @param openDomainObjects list of open domain objects from which a selection may be made.
	 */
	public void setOpenObjectChoices(List<T> openDomainObjects) {
		this.openDomainObjects = (openDomainObjects != null && !openDomainObjects.isEmpty())
				? new ArrayList<>(openDomainObjects)
				: null;
	}

	/**
	 * Get the selected domain object for read-only or immutable use.
	 * If an existing open object is selected its original mode applies but consumer will 
	 * be added.  The caller/consumer is responsible for releasing the returned domain object
	 * when done using it (see {@link DomainObject#release(Object)}).
	 * @param consumer domain object consumer
	 * @param immutable true if the domain object should be opened immutable, else false for
	 * read-only.  Immutable mode should not be used for content that will be modified.  If 
	 * read-only indicated an upgrade will always be performed if required.
	 * @return opened domain object or null if a file was not selected or if open failed to 
	 * complete.
	 */
	@SuppressWarnings("unchecked") // relies on content class filter
	public T getDomainObject(Object consumer, boolean immutable) {
		T dobj = null;
		if (usingOpenProgramList()) {
			dobj = getSelectedOpenDomainObject();
			if (dobj != null) {
				dobj.addConsumer(consumer);
			}
			return dobj;
		}
		int version = DomainFile.DEFAULT_VERSION;
		if (historyPanel != null) {
			version = historyPanel.getSelectedVersionNumber();
		}

		DomainFile domainFile = getDomainFile();
		if (domainFile != null) {
			GetDomainObjectTask task =
				new GetDomainObjectTask(consumer, domainFile, version, immutable);
			tool.execute(task, 1000);
			return (T) task.getDomainObject();
		}
		return null;
	}

	/**
	 * Return the selected version number from the history panel.
	 * @return -1 if a version history was not selected
	 */
	public int getVersion() {
		if (historyPanel != null && !usingOpenProgramList()) {
			return historyPanel.getSelectedVersionNumber();
		}
		return -1;
	}

	@Override
	public DomainFile getDomainFile() {
		if (usingOpenProgramList()) {
			return null;
		}
		return super.getDomainFile();
	}

	@Override
	public DomainFolder getDomainFolder() {
		if (usingOpenProgramList()) {
			return null;
		}
		return super.getDomainFolder();
	}

	@Override
	protected JPanel buildMainPanel() {

		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(super.buildMainPanel(), BorderLayout.CENTER);
		JPanel historyButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		historyButtonPanel.add(historyButton);
		mainPanel.add(historyButtonPanel, BorderLayout.SOUTH);
		mainPanel.setMinimumSize(new Dimension(200, HEIGHT));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setLeftComponent(mainPanel);
		splitPane.setOneTouchExpandable(true);

		splitPane.setDividerSize(0);
		splitPane.setDividerLocation(1.0);
		splitPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

		JPanel projectFilePanel = new JPanel(new BorderLayout());
		projectFilePanel.add(splitPane);

		String showHistory =
			Preferences.getProperty(SHOW_HISTORY_PREFERENCES_KEY, Boolean.FALSE.toString(), true);

		if (Boolean.parseBoolean(showHistory)) {
			showHistoryPanel(true);
		}

		openObjectsTable = null;
		tabbedPane = null;

		updateOkTooltip();

		if (openDomainObjects == null) {
			return projectFilePanel; // return Project File selection panel only
		}

		// Create tabbed pane with "Project Files" and "Open Program" tabs
		// NOTE: actual tab name reflects domainObjectClass name
		tabbedPane = new JTabbedPane();
		tabbedPane.setName("Tabs");
		tabbedPane.add("Project Files", projectFilePanel);
		tabbedPane.add("Open " + domainObjectClass.getSimpleName() + "s",
			buildOpenObjectsTable());

		tabbedPane.addChangeListener(e -> {
			int selectedTabIndex = tabbedPane.getModel().getSelectedIndex();
			if (selectedTabIndex == PROJECT_FILES_TAB) {
				// Project tree and History use
				String nameText = getNameText();
				setOkEnabled((nameText != null) && !nameText.isEmpty());
			}
			else { // OPEN_OBJECT_LIST_TAB
				setOkEnabled(getSelectedOpenDomainObject() != null);
			}
			updateOkTooltip();
		});

		JPanel tabbedPanel = new JPanel();
		tabbedPanel.setLayout(new BorderLayout());
		tabbedPanel.add(tabbedPane, BorderLayout.CENTER);

		tabbedPane.setSelectedIndex(PROJECT_FILES_TAB);
		return tabbedPanel;
	}

	private boolean usingOpenProgramList() {
		return tabbedPane != null &&
			tabbedPane.getModel().getSelectedIndex() == OPEN_OBJECT_LIST_TAB;
	}

	private T getSelectedOpenDomainObject() {
		if (!usingOpenProgramList()) {
			return null;
		}
		return openObjectsTable.getSelectedRowObject();
	}

	private Component buildOpenObjectsTable() {

		openObjectsTable = new GFilterTable<>(new OpenObjectsTableModel());
		GTable table = openObjectsTable.getTable();
		table.getSelectionModel()
			.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		openObjectsTable.addSelectionListener(e -> {
			setOkEnabled(true);
			okButton.setToolTipText("Use the selected " + domainObjectClass.getSimpleName());
		});

		table.addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				if (okButton.isEnabled()) {
					okCallback();
				}
			}
		});

		return openObjectsTable;
	}

	private void showHistoryPanel(boolean showHistory) {
		historyIsShowing = showHistory;
		if (showHistory) {
			createHistoryPanel();
			historyButton.setText("Hide History");
			DomainFile df = treePanel.getSelectedDomainFile();
			historyPanel.setDomainFile(df);
			splitPane.setDividerSize(DIVIDER_SIZE);
			splitPane.setDividerLocation(DEFAULT_WIDTH_NO_HISTORY - 4);
		}
		else {
			historyButton.setText("Show History>>");
			splitPane.setDividerSize(0);
			splitPane.setRightComponent(null);
			historyPanel = null;
		}

		Dimension size = getPreferredSizeForHistoryState();
		rootPanel.setPreferredSize(size);
		repack();
	}

	private Dimension getPreferredSizeForHistoryState() {
		int height = Integer.parseInt(
			Preferences.getProperty(HEIGHT_PREFERENCES_KEY, Integer.toString(HEIGHT)));

		String key = historyIsShowing ? WIDTH_WITH_HISTORY_PREFERENCES_KEY
				: WIDTH_NO_HISTORY_PREFERENCES_KEY;
		int defaultWidth = historyIsShowing ? DEFAULT_WIDTH_WITH_HISTORY : DEFAULT_WIDTH_NO_HISTORY;

		int width = Integer.parseInt(Preferences.getProperty(key, Integer.toString(defaultWidth)));

		return new Dimension(width, height);
	}

	private void savePreferences() {
		Dimension size = rootPanel.getSize();
		String propertyName = historyIsShowing ? WIDTH_WITH_HISTORY_PREFERENCES_KEY
				: WIDTH_NO_HISTORY_PREFERENCES_KEY;

		Preferences.setProperty(propertyName, Integer.toString(size.width));
		Preferences.setProperty(HEIGHT_PREFERENCES_KEY, Integer.toString(size.height));

		Preferences.setProperty(SHOW_HISTORY_PREFERENCES_KEY, Boolean.toString(historyIsShowing));
		Preferences.store();
	}

	@Override
	public void close() {
		savePreferences();
		historyPanel = null;
		super.close();
	}

	@Override
	protected void dialogShown() {
		super.dialogShown();

		for (DockingActionIf action : popupActions) {
			addAction(action);
		}
	}

	@Override
	protected void dialogClosed() {
		super.dialogClosed();

		for (DockingActionIf action : popupActions) {
			removeAction(action);
		}
	}

	private void updateOkTooltip() {
		String tip;
		if (usingOpenProgramList()) {
			tip = "Use selected " + domainObjectClass.getSimpleName();
		}
		else {
			tip = "Open the selected file";
			if (historyPanel != null && historyIsShowing) {
				int versionNumber = historyPanel.getSelectedVersionNumber();
				if (versionNumber >= 0) {
					DomainFile df = OpenVersionedFileDialog.super.getDomainFile();
					okButton.setToolTipText(
						"Open version " + versionNumber + " for " + df.getName());
				}
			}
		}
		okButton.setToolTipText(tip);
	}

	private boolean createHistoryPanel() {
		try {
			historyPanel = new VersionHistoryPanel(tool, null);
			popupActions = historyPanel.createPopupActions();
		}
		catch (IOException ioe) {
			Msg.debug(getClass(),
				"Error creating history panel for versioned file: " + ioe.getMessage(), ioe);
			return false;
		}

		historyPanel.setBorder(BorderFactory.createTitledBorder("Version History"));
		splitPane.setRightComponent(historyPanel);
		historyPanel.addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateOkTooltip();
		});
		return true;
	}

	private void init() {
		historyButton = new JButton("History>>");
		historyButton.addActionListener(e -> showHistoryPanel(!historyIsShowing));

		rootPanel.setPreferredSize(getPreferredSizeForHistoryState());
	}

	@Override
	protected void addTreeListeners() {
		super.addTreeListeners();

		treePanel.addTreeSelectionListener(e -> {
			if (historyPanel != null) {
				DomainFile df = treePanel.getSelectedDomainFile();
				historyPanel.setDomainFile(df);
			}
			updateOkTooltip();
		});
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContext context = super.getActionContext(event);
		if (context != null) {
			return context;
		}

		ActionContext actionContext = new DefaultActionContext(null, this, event.getComponent());
		actionContext.setMouseEvent(event);

		return actionContext;
	}

	private class OpenObjectsTableModel extends AbstractGTableModel<T> {

		@Override
		public String getName() {
			return "Open DomainObject List";
		}

		@Override
		public List<T> getModelData() {
			return openDomainObjects;
		}

		@Override
		public Object getColumnValueForRow(T t, int columnIndex) {
			// only one column
			return t.getDomainFile().toString();
		}

		@Override
		public int getColumnCount() {
			return 1;
		}

		@Override
		public String getColumnName(int columnIndex) {
			return "Program Path";
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return String.class;
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return false;
		}

	}
}
