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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.framework.main.datatree.VersionHistoryPanel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * Dialog to open a file that is versioned and allow a version to be
 * opened.
 *
 *
 */
public class OpenVersionedFileDialog extends DataTreeDialog {
	private static final String SHOW_HISTORY_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.SHOW_HISTORY";
	private static final String HEIGHT_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.HEIGHT";
	private static final String WIDTH_NO_HISTORY_PREFERENCES_KEY =
		"OPEN_PROGRAM_DIALOG.WIDTH_NO_HISTORY";
	private static final String WIDTH_WITH_HISTORY_PREFERENCES_KEY =
		"OPEN_PROGRAM_DIALOG.WIDTH_WITH_HISTORY";

	private final static int DEFAULT_WIDTH_NO_HISTORY = WIDTH;
	private final static int DEFAULT_WIDTH_WITH_HISTORY = 800;
	private final static int DIVIDER_SIZE = 2;

	private JSplitPane splitPane;
	private JButton historyButton;
	private JPanel mainPanel;
	private boolean historyIsShowing;
	private PluginTool tool;

	private VersionHistoryPanel historyPanel;
	private List<DockingActionIf> popupActions = Collections.emptyList();

	/**
	 * Constructor
	 * @param tool tool where the file is being opened.
	 * @param title title to use
	 * @param filter filter used to control what is displayed in data tree.
	 */
	public OpenVersionedFileDialog(PluginTool tool, String title, DomainFileFilter filter) {
		super(tool.getToolFrame(), title, DataTreeDialog.OPEN, filter);
		this.tool = tool;
		init();
	}

	/**
	 * Get the domain object for the selected version.
	 * @param consumer consumer
	 * @param readOnly true if the domain object should be opened read only,
	 * versus immutable
	 * @return null if a versioned file was not selected
	 */
	public DomainObject getVersionedDomainObject(Object consumer, boolean readOnly) {
		if (historyPanel != null) {
			return historyPanel.getSelectedVersion(consumer, readOnly);
		}
		return null;
	}

	/**
	 * Return the selected version number from the history panel.
	 * @return -1 if a version history was not selected
	 */
	public int getVersion() {
		if (historyPanel != null) {
			return historyPanel.getSelectedVersionNumber();
		}
		return -1;
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.main.DataTreeDialog#buildMainPanel()
	 */
	@Override
	protected JPanel buildMainPanel() {
		mainPanel = super.buildMainPanel();
		mainPanel.setMinimumSize(new Dimension(200, HEIGHT));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setLeftComponent(mainPanel);
		splitPane.setOneTouchExpandable(true);

		splitPane.setDividerSize(0);
		splitPane.setDividerLocation(1.0);
		splitPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

		JPanel outerPanel = new JPanel(new BorderLayout());
		outerPanel.add(splitPane);

		String showHistory =
			Preferences.getProperty(SHOW_HISTORY_PREFERENCES_KEY, Boolean.FALSE.toString(), true);

		if (Boolean.parseBoolean(showHistory)) {
			showHistoryPanel(true);
		}

		return outerPanel;
	}

	private void advancedButtonCallback() {
		showHistoryPanel(!historyIsShowing);

	}

	private void showHistoryPanel(boolean showHistory) {
		historyIsShowing = showHistory;
		if (showHistory) {
			createHistoryPanel();
			historyButton.setText("No History");
			DomainFile df = treePanel.getSelectedDomainFile();
			historyPanel.setDomainFile(df);
			splitPane.setDividerSize(DIVIDER_SIZE);
			splitPane.setDividerLocation(DEFAULT_WIDTH_NO_HISTORY - 4);
		}
		else {
			historyButton.setText("History>>");
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
			okButton.setToolTipText("Open the selected file");
			int versionNumber = historyPanel.getSelectedVersionNumber();
			if (versionNumber >= 0) {
				DomainFile df = OpenVersionedFileDialog.super.getDomainFile();
				okButton.setToolTipText("Open version " + versionNumber + " for " + df.getName());
			}
		});
		return true;
	}

	private void init() {
		historyButton = new JButton("History>>");
		historyButton.addActionListener(e -> advancedButtonCallback());
		addButton(historyButton);

		okButton.setToolTipText("Open the selected file");
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
		});
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContext context = super.getActionContext(event);
		if (context != null) {
			return context;
		}

		ActionContext actionContext = new ActionContext(null, this, event.getComponent());
		actionContext.setMouseEvent(event);

		return actionContext;
	}
}
