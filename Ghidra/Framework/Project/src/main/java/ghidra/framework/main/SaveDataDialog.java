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
import java.awt.event.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.ListPanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Modal dialog to display a list of domain objects that have changed.
 * The user can mark the ones to save, or pop up another dialog to save
 * the files to a different location and/or name.
 * Read-only files are rendered in red and the checkboxes for these files
 * cannot be selected.
 * If the project has changed, then the first checkbox displayed will be
 * for saving the project configuration.
 */
public class SaveDataDialog extends DialogComponentProvider {

	private final static String SELECT_ALL = "Select All";
	private final static String DESELECT_ALL = "Select None";

	private ListPanel listPanel;
	private JPanel mainPanel;
	private GCheckBox[] checkboxes;
	private List<DomainFile> files;
	private boolean[] saveable;
	private JButton selectAllButton;
	private JButton deselectAllButton;
	private JButton yesButton;
	private JButton noButton;
	private PluginTool tool;

	/** This class gets run as a task and this flag signals a user cancel */
	private boolean operationCompleted;

	/**
	 * Construct new SaveDataDiaog
	 * @param tool front end tool
	 */
	public SaveDataDialog(PluginTool tool) {

		super("Save Modified Files", true);
		setHelpLocation(new HelpLocation("FrontEndPlugin", "SaveDataDialog"));

		this.tool = tool;
		mainPanel = createPanel();
		addWorkPanel(mainPanel);

		yesButton = new JButton("Save");
		yesButton.setMnemonic('S');
		addButton(yesButton);
		yesButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				okCallback();
			}
		});
		noButton = new JButton("Don't Save");
		noButton.setMnemonic('n');
		noButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent evt) {
				operationCompleted = true;
				close();
			}
		});
		addButton(noButton);
		addCancelButton();

		addListeners();
	}

	/**
	 * Shows the save dialog with the given domain files, but no options to save
	 * the project.  The dialog will not appear if there is no data that needs
	 * saving.
	 * 
	 * @param domainFiles The files that may need saving.
	 * @return true if the user hit the 'Save' or 'Don't Save' option; return false if the
	 *         user cancelled the operation
	 */
	public boolean showDialog(List<DomainFile> domainFiles) {
		clearStatusText();
		operationCompleted = false;

		files = domainFiles;

		initList();

		if (!files.isEmpty()) {
			tool.showDialog(this);
		}
		else {
			operationCompleted = true;
		}

		return operationCompleted;
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	protected void okCallback() {

		List<DomainFile> list = new ArrayList<>();

		for (int i = 0; i < checkboxes.length; i++) {
			if (checkboxes[i].isSelected()) {
				list.add(files.get(i));
			}
		}
		if (list.size() > 0) {
			DomainFile[] deleteFiles = new DomainFile[list.size()];
			SaveTask task = new SaveTask(list.toArray(deleteFiles));
			new TaskLauncher(task, getComponent());
		}
		else {
			operationCompleted = true;
			close();
		}
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		close();

	}

	/**
	 * Create the panel for this dialog.
	 */
	private JPanel createPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		JPanel parentPanel = new JPanel(new BorderLayout());

		//
		// Create Button Panel
		//
		selectAllButton = new JButton(SELECT_ALL);
		selectAllButton.setMnemonic('A');
		deselectAllButton = new JButton(DESELECT_ALL);
		deselectAllButton.setMnemonic('N');

		JPanel buttonPanel = ButtonPanelFactory.createButtonPanel(
			new JButton[] { selectAllButton, deselectAllButton });

		//
		// List Panel
		//
		listPanel = new ListPanel();
		listPanel.setCellRenderer(new DataCellRenderer());
		listPanel.setMouseListener(new ListMouseListener());

		// Layout Main Panel
		parentPanel.add(buttonPanel, BorderLayout.EAST);
		parentPanel.add(listPanel, BorderLayout.CENTER);
		parentPanel.setBorder(new TitledBorder("Data"));

		panel.add(parentPanel, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Add listeners to the buttons.
	 */
	private void addListeners() {
		selectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				selectAll();
			}
		});

		deselectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				deselectAll();
			}
		});

	}

	/**
	 * Select all files to be saved.
	 */
	private void selectAll() {

		clearStatusText();

		for (int i = 0; i < checkboxes.length; i++) {
			if (saveable[i]) {
				checkboxes[i].setSelected(true);
			}
		}
		listPanel.repaint();
	}

	/**
	 * Clear selected checkboxes.
	 */
	private void deselectAll() {
		clearStatusText();
		for (GCheckBox checkboxe : checkboxes) {
			checkboxe.setSelected(false);
		}
		listPanel.repaint();
	}

	private List<DomainFile> checkForUnsavedFiles(List<DomainFile> domainFiles) {

		List<DomainFile> unsavedFiles = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isChanged()) {
				unsavedFiles.add(domainFile);
			}
		}
		return unsavedFiles;
	}

	private void initList() {

		// initList() may be called multiple times within one dialog showing,
		// and some files may have been changed, so we need to update the list
		files = checkForUnsavedFiles(files);
		checkboxes = new GCheckBox[files.size()];
		saveable = new boolean[files.size()];
		String readOnlyString = " (Read-Only)";
		yesButton.setEnabled(false);
		for (int i = 0; i < files.size(); i++) {
			checkboxes[i] = new GCheckBox(files.get(i).getName());
			checkboxes[i].setBackground(Color.white);
			saveable[i] = files.get(i).canSave();
			if (!saveable[i]) {
				String text = files.get(i).getName() + readOnlyString;
				if (!files.get(i).isInWritableProject()) {
					ProjectLocator projectLocator = files.get(i).getProjectLocator();
					if (projectLocator != null) {
						text = files.get(i).getName() + " (Read-Only from " +
							files.get(i).getProjectLocator().getName() + ")";
					}
				}
				checkboxes[i].setText(text);
			}
			else {
				checkboxes[i].setSelected(true);
				yesButton.setEnabled(true);
			}

		}
		listPanel.refreshList(checkboxes);
		setFocusComponent(yesButton);//.requestFocusInWindow();
	}

	/////////////////////////////////////////////////////////////////////////
	/**
	 * Cell renderer to show the checkboxes for the changed data files.
	 */
	private class DataCellRenderer implements ListCellRenderer<JCheckBox> {

		private Font boldFont;

		@Override
		public Component getListCellRendererComponent(JList<? extends JCheckBox> list,
				JCheckBox value, int index, boolean isSelected, boolean cellHasFocus) {

			if (boldFont == null) {
				Font font = list.getFont();
				boldFont = new Font(font.getName(), font.getStyle() | Font.BOLD, font.getSize());
			}

			// set color to red if file cannot be saved 'as is'
			if (!saveable[index]) {
				checkboxes[index].setForeground(Color.red);
				checkboxes[index].setFont(boldFont);
			}
			return checkboxes[index];
		}
	}

	/**
	 * Mouse listener to get the selected cell in the list.
	 */
	private class ListMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {

			clearStatusText();
			JList list = (JList) e.getSource();
			int index = list.locationToIndex(e.getPoint());
			if (index < 0) {
				return;
			}

			if (!saveable[index]) {
				setStatusText(
					files.get(index).getPathname() + " cannot be saved to current location");
				return;
			}
			boolean selected = checkboxes[index].isSelected();
			checkboxes[index].setSelected(!selected);
			listPanel.repaint();
		}
	}

	/////////////////////////////////////////////////////////////////////////
	/**
	 * Task to save files.
	 */
	private class SaveTask extends Task {
		private DomainFile[] domainFiles;

		SaveTask(DomainFile[] files) {
			super(files.length > 1 ? "Saving Files..." : "Saving File", true, true, true);
			this.domainFiles = files;
		}

		/**
		 * @see ghidra.util.task.Task#run(TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (DomainFile domainFile : domainFiles) {
					if (monitor.isCancelled()) {
						break;
					}
					monitor.setProgress(0);
					monitor.setMessage("Saving " + domainFile.getName());
					domainFile.save(monitor);
				}
				operationCompleted = !monitor.isCancelled();

			}
			catch (CancelledException ce) {
				// this is OK, it will be handled below
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Error Saving Data", "Unexpected exception saving data!",
					t);
			}
			if (operationCompleted) {
				try {
					SwingUtilities.invokeAndWait(new Runnable() {
						@Override
						public void run() {
							close();
						}
					});
				}
				catch (InterruptedException e) {
					// don't care?
				}
				catch (InvocationTargetException e) {
					// don't care?
				}
			}
			else if (monitor.isCancelled()) {
				updateList();
			}
		}

		/**
		 * Refresh the list of files that need saving.
		 */
		private void updateList() {
			Runnable r = new Runnable() {
				@Override
				public void run() {
					initList();
				}
			};
			try {
				SwingUtilities.invokeAndWait(r);
			}
			catch (Exception e) {
				// don't care?
			}
		}
	}
}
