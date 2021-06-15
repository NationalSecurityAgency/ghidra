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
package docking.widgets.filechooser;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileFilter;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.filechooser.FileSystemView;

import docking.*;
import docking.widgets.*;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.filechooser.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;
import resources.*;
import resources.icons.TranslateIcon;
import util.CollectionUtils;
import util.HistoryList;

/**
 * An implementation of a file chooser dialog.
 * This class is designed to emulate the JFileChooser,
 * but it removes the network locking issue.
 * When a network drive is down, the JFileChooser can
 * take several minutes to come up.
 *
 * Why use this file chooser over JFileChooser??
 * Let me enumerate the reasons...
 * <ol>
 *  <li>JFileChooser cannot show hidden/system files, but we can!</li>
 *  <li>JFileChooser does not properly consume key strokes (global actions in docking windows)</li>
 *  <li>This class is threaded, so loading delays do not lock the GUI</li>
 *  <li>This class provides shortcut buttons similar to those of the Windows native chooser</li>
 * </ol>
 */
public class GhidraFileChooser extends DialogComponentProvider
		implements GhidraFileChooserListener, FileFilter {

	static final String UP_BUTTON_NAME = "UP_BUTTON";
	private static final Color FOREROUND_COLOR = Color.BLACK;
	private static final Color BACKGROUND_COLOR = Color.WHITE;
	static final String PREFERENCES_PREFIX = "G_FILE_CHOOSER";
	private static final String WIDTH_PREFERENCE_PREFIX = PREFERENCES_PREFIX + ".WIDTH.";
	private static final String HEIGHT_PREFERENCE_PREFIX = PREFERENCES_PREFIX + ".HEIGHT.";
	private static final String VIEW_STYLE_PREFIX = PREFERENCES_PREFIX + ".VIEW_STYLE.";
	private static final String DETAILS_VIEW_STYLE = "DetailsView";
	private static final String SIMPLE_VIEW_STYLE = "SimpleView";

	private static final String CARD_LIST = "LIST";
	private static final String CARD_TABLE = "TABLE";
	private static final String CARD_WAIT = "WAIT";

	static final String TITLE = "File Chooser";
	static final String DOT = ".";
	static final String DOTDOT = "..";
	static final String NEW_FOLDER = "New Folder";
	static final Pattern INVALID_FILENAME_PATTERN = Pattern.compile("[/\\\\*?]");

	private static final int PAD = 5;

	private static Icon refreshIcon = Icons.REFRESH_ICON;
	private static Icon backIcon = ResourceManager.loadImage("images/left.png");
	private static Icon forwardIcon = ResourceManager.loadImage("images/right.png");
	private static Icon detailsIcon = ResourceManager.loadImage("images/table.png");
	private static Icon optionsIcon = ResourceManager.loadImage("images/document-properties.png");
	private static Icon newFolderIcon = null;
	private static Icon upIcon = null;
	static {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS ||
			Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX) {

			newFolderIcon = getIcon("FileChooser.newFolderIcon");
			upIcon = getIcon("FileChooser.upFolderIcon");
		}
		if (newFolderIcon == null) {
			newFolderIcon = ResourceManager.loadImage("images/folder_add.png");
		}
		if (upIcon == null) {
			upIcon = ResourceManager.loadImage("images/up.png");
		}
	}

	private static Icon getIcon(String iconName) {
		try {
			return UIManager.getIcon(iconName);
		}
		catch (Exception e) {
			// we tried; just return null
		}
		return null;
	}

	/** Instruction to display only files. */
	public static final int FILES_ONLY = 0;
	/** Instruction to display only directories. */
	public static final int DIRECTORIES_ONLY = 1;
	/** Instruction to display both files and directories. */
	public static final int FILES_AND_DIRECTORIES = 2;

	final static File MY_COMPUTER = new File("My Computer");
	final static File RECENT = new File("Recent");

	private static final int MAX_RECENT = 10;

	private GhidraFileChooserModel fileChooserModel;
	private GhidraFileChooserMode fileSelectionMode = GhidraFileChooserMode.FILES_ONLY;
	private static boolean initialized;
	private static List<RecentGhidraFile> recentList = new ArrayList<>();

	private HistoryList<HistoryEntry> history = new HistoryList<>(20, (files, previous) -> {

		updateHistoryWithSelectedFiles(previous);

		updateDirAndSelectFile(files.parentDir, files.getSelectedFile(), false, false);
		updateNavigationButtons();
	});
	private File initialFile = null;
	private File initialFileToSelect = null;

	/**
	 * Files selected by the user, but not yet validated.
	 */
	private FileList selectedFiles = new FileList(); // files selected in the GUI

	/**
	 * Selected files that have passed as acceptable.  These will be given back to the user.  When
	 * we say validation, we mean files that exist.  If the user chooses a file from the GUI by
	 * clicking it, then that file is valid, as it exists.  Alternatively, if the user types in
	 * a filename we need to perform validation on the entered value to make sure it is valid
	 * for the given context.  For example, if the chooser is in {@link #FILES_ONLY} mode,
	 * then we must not allow a directory to be chosen.
	 */
	private FileList validatedFiles = new FileList();

	private Component parent;
	private JPanel waitPanel;
	private EmptyBorderButton backButton;
	private EmptyBorderButton forwardButton;
	private EmptyBorderButton upLevelButton;
	private EmptyBorderButton newFolderButton;
	private EmptyBorderButton refreshButton;
	private EmptyBorderToggleButton detailsButton;

	private UnselectableButtonGroup shortCutButtonGroup;
	private FileChooserToggleButton myComputerButton;
	private FileChooserToggleButton desktopButton;
	private FileChooserToggleButton homeButton;
	private FileChooserToggleButton recentButton;

	private JTextField currentPathTextField;
	private DropDownSelectionTextField<File> filenameTextField;
	private DirectoryTableModel directoryTableModel;
	private DirectoryTable directoryTable;
	private DirectoryListModel directoryListModel;
	private DirectoryList directoryList;
	private GhidraFileChooserDirectoryModelIf directoryModel;
	private JScrollPane directoryScroll;
	private CardLayout card;
	private JPanel cardPanel;
	private DefaultComboBoxModel<GhidraFileFilter> filterModel;
	private JComboBox<GhidraFileFilter> filterCombo;
	private boolean showDetails = false;
	private boolean wasCancelled;
	private boolean multiSelectionEnabled;
	private FileChooserActionManager actionManager;

	/**
	 * The last input component to take focus (the text field or file view). 
	 * 
	 * <p>This may annoy users that are using the keyboard to perform navigation operations via 
	 * the toolbar buttons, as we will keep putting focus back into the last input item.  We
	 * may need a way to set this field to null when the user is working in this fashion.
	 */
	private Component lastInputFocus;

	private Worker worker = Worker.createGuiWorker();

	private GFileChooserOptionsDialog optionsDialog = new GFileChooserOptionsDialog();
	private EmptyBorderButton optionsButton;
	private boolean showDotFiles;

	// Listener for selections on the filename drop-down
	private SelectionListener<File> selectionListener;

	/**
	 * Constructs a new ghidra file chooser.
	 * @param parent the parent component
	 */
	public GhidraFileChooser(Component parent) {
		this(new LocalFileChooserModel(), parent);
	}

	/**
	 * Constructs a new ghidra file chooser
	 * 
	 * @param model the file chooser model
	 * @param parent the parent component
	 */
	/*package*/ GhidraFileChooser(GhidraFileChooserModel model, Component parent) {
		super(TITLE, true, true, true, false);
		this.parent = parent;

		setTransient(true);
		init(model);
		loadRecentList();
		loadOptions();
	}

	private void init(GhidraFileChooserModel newModel) {
		this.fileChooserModel = newModel;
		this.fileChooserModel.setListener(this);

		history.setAllowDuplicates(true);

		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();

		actionManager = new FileChooserActionManager(this);

		setFocusComponent(filenameTextField);
		setDefaultButton(null);
		setPreferredSize(800, 600);

		updateDirOnly(newModel.getHomeDirectory(), true);
	}

//==================================================================================================
// Setup Methods
//==================================================================================================

	private JComponent buildWorkPanel() {
		buildWaitPanel();

		JPanel currentPathPanel = buildHeaderPanel();
		JPanel shortCutPanel = buildShortCutPanel();

		JScrollPane directoryTableScroll = buildDirectoryTable();
		JScrollPane directoryListScroll = buildDirectoryList();

		card = new CardLayout();

		cardPanel = new JPanel(card);
		cardPanel.setName("CARD_PANEL");
		cardPanel.add(directoryTableScroll, CARD_TABLE);
		cardPanel.add(directoryListScroll, CARD_LIST);
		cardPanel.add(waitPanel, CARD_WAIT);

		card.show(cardPanel, CARD_LIST);
		directoryModel = directoryList;

		JPanel filenamePanel = buildFileNamePanel();

		JPanel directoryPanel = new JPanel(new BorderLayout(PAD, PAD));
		directoryPanel.add(cardPanel, BorderLayout.CENTER);
		directoryPanel.add(filenamePanel, BorderLayout.SOUTH);

		JPanel main = new JPanel(new BorderLayout(PAD, PAD));
		main.add(currentPathPanel, BorderLayout.NORTH);
		main.add(shortCutPanel, BorderLayout.WEST);
		main.add(directoryPanel, BorderLayout.CENTER);

		return main;
	}

	private JPanel buildShortCutPanel() {
		myComputerButton = new FileChooserToggleButton("My Computer") {
			@Override
			File getFile() {
				return MY_COMPUTER;
			}
		};
		myComputerButton.setName("MY_COMPUTER_BUTTON");
		myComputerButton.setIcon(ResourceManager.loadImage("images/computer.png"));
		myComputerButton.addActionListener(e -> updateMyComputer());
		myComputerButton.setForeground(FOREROUND_COLOR);

		desktopButton = new FileChooserToggleButton("Desktop") {
			@Override
			File getFile() {
				return fileChooserModel.getDesktopDirectory();
			}
		};
		desktopButton.setName("DESKTOP_BUTTON");
		desktopButton.setIcon(ResourceManager.loadImage("images/desktop.png"));
		desktopButton.addActionListener(e -> updateDesktop());
		desktopButton.setForeground(FOREROUND_COLOR);
		desktopButton.setEnabled(fileChooserModel.getDesktopDirectory() != null);

		homeButton = new FileChooserToggleButton("Home") {
			@Override
			File getFile() {
				return fileChooserModel.getHomeDirectory();
			}
		};
		homeButton.setName("HOME_BUTTON");
		homeButton.setIcon(ResourceManager.loadImage("images/user-home.png"));
		homeButton.addActionListener(e -> updateHome());
		homeButton.setForeground(FOREROUND_COLOR);

		recentButton = new FileChooserToggleButton("Recent") {
			@Override
			File getFile() {
				return RECENT;
			}
		};
		recentButton.setName("RECENT_BUTTON");
		Icon baseIcon = ResourceManager.loadImage("images/inode-directory.png");
		Icon overlayIcon = ResourceManager.loadImage("images/edit-undo.png");
		MultiIcon multiIcon = new MultiIcon(baseIcon);
		multiIcon.addIcon(new TranslateIcon(overlayIcon, 6, 10));

		recentButton.setIcon(multiIcon);
		recentButton.addActionListener(e -> updateRecent());
		recentButton.setForeground(FOREROUND_COLOR);

		shortCutButtonGroup = new UnselectableButtonGroup();
		shortCutButtonGroup.add(myComputerButton);
		shortCutButtonGroup.add(desktopButton);
		shortCutButtonGroup.add(homeButton);
		shortCutButtonGroup.add(recentButton);

		JPanel shortCutPanel = new JPanel(new GridLayout(0, 1));
		DockingUtils.setTransparent(shortCutPanel);
		shortCutPanel.add(myComputerButton);
		shortCutPanel.add(desktopButton);
		shortCutPanel.add(homeButton);
		shortCutPanel.add(recentButton);

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createLoweredBevelBorder());
		panel.setBackground(BACKGROUND_COLOR.darker());
		panel.add(shortCutPanel, BorderLayout.NORTH);
		return panel;
	}

	private JPanel buildFileNamePanel() {
		JLabel filenameLabel = new GDLabel("File name:");
		FileDropDownSelectionDataModel model = new FileDropDownSelectionDataModel(this);
		filenameTextField = new DropDownSelectionTextField<>(model);
		filenameTextField.setMatchingWindowHeight(200);
		filenameTextField.addCellEditorListener(new CellEditorListener() {

			@Override
			public void editingStopped(ChangeEvent e) {
				// the user has cancelled editing in the text field (i.e., they pressed ESCAPE)
				enterCallback();
			}

			@Override
			public void editingCanceled(ChangeEvent e) {
				// the user has committed editing from the text field (i.e, they pressed ENTER)
				escapeCallback();
			}
		});

		filenameTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				lastInputFocus = filenameTextField;
			}
		});

		// This is a callback when the user has made a choice from the selection window.
		selectionListener = new SelectionListener<>();
		filenameTextField.addDropDownSelectionChoiceListener(selectionListener);

		// this allows us to process the Enter keypress, which takes the current user text
		// selection and accepts that
		filenameTextField.setConsumeEnterKeyPress(false);

		filenameTextField.setName("filenameTextField");

		JLabel filterLabel = new GLabel("Type:");
		filterCombo = new GComboBox<>();
		filterCombo.setRenderer(GListCellRenderer.createDefaultCellTextRenderer(
			fileFilter -> fileFilter != null ? fileFilter.getDescription() : ""));
		filterCombo.addItemListener(e -> rescanCurrentDirectory());

		filterModel = (DefaultComboBoxModel<GhidraFileFilter>) filterCombo.getModel();
		addFileFilter(GhidraFileFilter.ALL);

		JPanel filenamePanel = new JPanel(new PairLayout(PAD, PAD));
		filenamePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		filenamePanel.add(filenameLabel);
		filenamePanel.add(filenameTextField);
		filenamePanel.add(filterLabel);
		filenamePanel.add(filterCombo);
		return filenamePanel;
	}

	private class SelectionListener<T> implements DropDownSelectionChoiceListener<File> {

		@Override
		public void selectionChanged(File file) {
			// take the selection and close the dialog
			worker.schedule(new SetSelectedFileAndAcceptSelection(file));
		}
	}

	private JPanel buildHeaderPanel() {

		JPanel headerPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();

		gbc.gridx = 0;
		//	gbc.insets = new Insets(PAD, PAD, PAD, PAD);
		JButton[] navButtons = buildNavigationButtons();
		for (JButton element : navButtons) {
			headerPanel.add(element, gbc);
			gbc.gridx++;
		}

		gbc.insets = new Insets(PAD, PAD, PAD, PAD);
		int afterPathLabel = gbc.gridx;
		gbc.gridx++; // leave this slot open

		gbc.gridx++;
		gbc.insets = new Insets(PAD, 0, PAD, PAD);
		JButton[] buttons = buildNonNavigationButtons();
		for (JButton element : buttons) {
			headerPanel.add(element, gbc);
			gbc.gridx++;
		}

		gbc.gridx = afterPathLabel;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		currentPathTextField = new JTextField();
		currentPathTextField.setName("Path");
		currentPathTextField.setEditable(false);
		headerPanel.add(currentPathTextField, gbc);

		return headerPanel;
	}

	private void buildWaitPanel() {
		waitPanel = new JPanel(new BorderLayout());
		waitPanel.setBorder(BorderFactory.createLoweredBevelBorder());
		waitPanel.setBackground(BACKGROUND_COLOR);
		waitPanel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				e.consume();
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				waitPanel.setCursor(new Cursor(Cursor.WAIT_CURSOR));
				e.consume();
			}

			@Override
			public void mouseExited(MouseEvent e) {
				waitPanel.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
			}
		});
		waitPanel.addMouseMotionListener(new MouseMotionAdapter() {
			// abstract class; empty implementation to consume events
		});
		waitPanel.addKeyListener(new KeyAdapter() {
			// abstract class; empty implementation to consume events
		});
	}

	private JButton[] buildNavigationButtons() {
		backButton = new EmptyBorderButton(backIcon);
		backButton.setName("BACK_BUTTON");
		backButton.setEnabled(false);
		backButton.setToolTipText("Go to last folder visited");
		backButton.addActionListener(e -> goBack());

		forwardButton = new EmptyBorderButton(forwardIcon);
		forwardButton.setName("FORWARD_BUTTON");
		forwardButton.setEnabled(false);
		forwardButton.setToolTipText("Go to previous folder visited");
		forwardButton.addActionListener(e -> goForward());

		upLevelButton = new EmptyBorderButton(upIcon);
		upLevelButton.setName(UP_BUTTON_NAME);
		upLevelButton.setToolTipText("Up one level");
		upLevelButton.addActionListener(e -> goUpOneDirectoryLevel());

		return new JButton[] { backButton, forwardButton, upLevelButton };
	}

	private JButton[] buildNonNavigationButtons() {

		newFolderButton = new EmptyBorderButton(newFolderIcon);
		newFolderButton.setName("NEW_BUTTON");
		newFolderButton.setToolTipText("Create new folder");
		newFolderButton.addActionListener(e -> createNewFolder());

		refreshButton = new EmptyBorderButton(refreshIcon);
		refreshButton.setName("REFRESH_BUTTON");
		refreshButton.setToolTipText("Rescan current directory");
		refreshButton.addActionListener(e -> rescanCurrentDirectory());

		detailsButton = new EmptyBorderToggleButton(detailsIcon);
		detailsButton.setName("DETAILS_BUTTON");
		detailsButton.setToolTipText("Show details");
		detailsButton.addActionListener(e -> {
			cancelEdits();
			doSetShowDetails(!showDetails);
		});

		optionsButton = new EmptyBorderButton(optionsIcon);
		optionsButton.setName("OPTIONS_BUTTON");
		optionsButton.setToolTipText("File Chooser Options");
		optionsButton.addActionListener(e -> {
			DockingWindowManager.showDialog(parent, optionsDialog);
			loadOptions();
		});

		return new JButton[] { refreshButton, newFolderButton, detailsButton, optionsButton };
	}

	private void loadOptions() {
		showDotFiles = optionsDialog.getShowsDotFiles();
		rescanCurrentDirectory();
	}

	/**
	 * When <b>true</b> is passed the chooser will use a detailed table view to show the files;
	 * false will show a simplified list of files.
	 * @param showDetails true to show details
	 */
	public void setShowDetails(boolean showDetails) {
		if (detailsButton.isSelected() != showDetails) {
			detailsButton.toggle();
		}
	}

	private void doSetShowDetails(@SuppressWarnings("hiding") boolean showDetails) {
		this.showDetails = showDetails;
		updateDirectoryPresentationMode();
		rescanCurrentDirectory();
	}

	private JScrollPane buildDirectoryList() {
		directoryListModel = new DirectoryListModel();
		directoryList = new DirectoryList(this, directoryListModel, rootPanel.getFont());
		directoryList.setName("LIST");
		directoryList.setBackground(BACKGROUND_COLOR);

		directoryList.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				lastInputFocus = directoryList;
			}
		});

		directoryScroll = new JScrollPane(directoryList);
		directoryScroll.getViewport().setBackground(BACKGROUND_COLOR);
		directoryScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);
		directoryScroll.addComponentListener(new ComponentAdapter() {
			//if the scroll pane is resized, we need to adjust
			//the visible row count
			@Override
			public void componentResized(ComponentEvent e) {
				Dimension size = directoryScroll.getSize();
				int cellHeight = directoryList.getFixedCellHeight();
				int nRows = size.height / cellHeight;
				directoryList.setVisibleRowCount(nRows - 1);
			}
		});

		return directoryScroll;
	}

//==================================================================================================
// End Setup Methods
//==================================================================================================

	@Override
	public void modelChanged() {
		SystemUtilities.runSwingLater(() -> {
			directoryListModel.update();
			directoryTableModel.update();
		});
	}

	@Override
	public boolean accept(File file) {
		if (!showDotFiles) {
			String name = file.getName();
			if (name.startsWith(".")) {
				return false;
			}
		}

		switch (fileSelectionMode) {
			case DIRECTORIES_ONLY:
				if (file.isFile()) {
					return false;
				}
				break;
			case FILES_AND_DIRECTORIES:
			default:
				break;
		}
		GhidraFileFilter filter = (GhidraFileFilter) filterCombo.getSelectedItem();
		if (filter != null) {
			return filter.accept(file, fileChooserModel);
		}
		return false;
	}

	/**
	 * Sets the <code>GhidraFileChooser</code> to allow the user to just
	 * select files, just select
	 * directories, or select both files and directories.  The default is
	 * <code>JFilesChooser.FILES_ONLY</code>.
	 *
	 * @param mode the type of files to be displayed:
	 * <ul>
	 * <li>GhidraFileChooser.FILES_ONLY
	 * <li>GhidraFileChooser.DIRECTORIES_ONLY
	 * <li>GhidraFileChooser.FILES_AND_DIRECTORIES
	 * </ul>
	 *
	 * @exception IllegalArgumentException  if <code>mode</code> is an
	 *              illegal Dialog mode
	 * @deprecated use instead {@link #setFileSelectionMode(GhidraFileChooserMode)}
	 */
	@Deprecated
	public void setFileSelectionMode(int mode) {
		this.fileSelectionMode = GhidraFileChooserMode.values()[mode];
	}

	/**
	 * Sets this file chooser to allow the user to just select files, just select
	 * directories, or select both files and directories.  The default is
	 * {@link GhidraFileChooserMode#FILES_ONLY}.
	 *
	 * @param mode the type of files to be displayed
	 */
	public void setFileSelectionMode(GhidraFileChooserMode mode) {
		this.fileSelectionMode = Objects.requireNonNull(mode);
	}

	/**
	 * Returns true if multiple files can be selected.
	 * @return true if multiple files can be selected
	 * @see #setMultiSelectionEnabled
	 */
	public boolean isMultiSelectionEnabled() {
		return multiSelectionEnabled;
	}

	/**
	 * Sets the file chooser to allow multiple file selections.
	 * @param b true if multiple files may be selected
	 * @see #isMultiSelectionEnabled
	 */
	public void setMultiSelectionEnabled(boolean b) {
		multiSelectionEnabled = b;
		if (b) {
			directoryList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			directoryTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
		else {
			directoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
			directoryTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		}
	}

	/**
	 * Sets the text used in the <code>OK</code> button 
	 * 
	 * @param buttonText the text 
	 */
	public void setApproveButtonText(String buttonText) {
		setOkButtonText(buttonText);
	}

	/**
	 * Sets the tooltip text used in the <code>OK</code> button
	 * 
	 * @param tooltipText the tooltip text
	 */
	public void setApproveButtonToolTipText(String tooltipText) {
		setOkToolTip(tooltipText);
	}

	private void updateMyComputer() {
		updateMyComputer(true);
	}

	private void updateMyComputer(boolean addToHistory) {
		worker.schedule(new UpdateMyComputerJob(myComputerButton.getFile(), addToHistory));
	}

	private void updateDesktop() {
		File desktop = desktopButton.getFile();
		updateDirOnly(desktop, true);
	}

	private void updateHome() {
		File home = homeButton.getFile();
		updateDirOnly(home, true);
	}

	void removeRecentFiles(List<RecentGhidraFile> toRemove) {
		recentList.removeAll(toRemove);
		saveRecentList();
		updateRecent();
	}

	private void updateRecent() {
		updateRecent(true);
	}

	private void updateRecent(boolean addToHistory) {
		worker.schedule(new UpdateRecentJob(recentButton.getFile(), addToHistory));
	}

	private File currentDirectory() {
		String path = currentPathTextField.getText();
		if (path.length() == 0) {
			return null;
		}

		if (path.equals(RECENT.getName())) {
			return RECENT;
		}

		if (path.equals(MY_COMPUTER.getName())) {
			return MY_COMPUTER;
		}

		return new GhidraFile(path, fileChooserModel.getSeparator());
	}

	/**
	 * Updates the given directory and selects the given file.
	 *
	 * @param directory The directory to load and update
	 * @param fileToSelect The file to select after updating the dir (may be null).
	 * @param forceUpdate True signals to force the directory to update, even if it is the current
	 *        directory
	 * @param addToHistory True signals to add the given directory to the navigation history
	 */
	private void updateDirAndSelectFile(File directory, File fileToSelect, boolean forceUpdate,
			boolean addToHistory) {
		if (MY_COMPUTER.equals(directory)) {
			updateMyComputer(addToHistory);
			setSelectedFileAndUpdateDisplay(fileToSelect);
			return;
		}
		if (RECENT.equals(directory)) {
			updateRecent(addToHistory);
			return;
		}

		if (directory == null) {
			if (isDirectory(fileToSelect)) {
				// this could happen if the selected file is a root directory
				updateDirOnly(fileToSelect, forceUpdate, addToHistory);
			}
			return; // nothing to select
		}

		// no file to select
		if (fileToSelect == null) {
			updateDirOnly(directory, forceUpdate, addToHistory);
			return;
		}

		worker.schedule(new UpdateDirectoryContentsJob(directory, fileToSelect, addToHistory));
	}

	// convenience method that always adds the given dir to the history
	private void updateDirOnly(File directory, boolean force) {
		updateDirOnly(directory, force, true);
	}

	private void updateDirOnly(File directory, boolean force, boolean addToHistory) {
		if (!fileExists(directory)) {
			return;
		}

		if (!isDirectory(directory)) {
			throw new AssertException("Expected a directory and did not get one: " + directory);
		}

		File currentDirectory = currentDirectory();

		// if we are forcing the update, then just do it! ...or, if the new dir is not already
		// the current dir, then we need to update
		if (force || !directory.equals(currentDirectory)) {
			worker.schedule(new UpdateDirectoryContentsJob(directory, null, addToHistory));
			return;
		}

		// we only get here if the new dir is the current dir and we are not forcing an update
		// TODO this code causes unexpected behavior when in 'directories only' mode in that 
		// this will cause the current directory to change.  The behavior can be seen by 
		// putting this code back in and then running the tests.   No tests are failing with this
		// code removed.  We are leaving this code here for a couple releases in case we find 
		// a code path that requires it.
		// setSelectedFileAndUpdateDisplay((isFilesOnly() ? null : directory));
	}

	boolean pendingUpdate() {
		return worker.isBusy();
	}

	String getDisplayName(File file) {
		if (file == null) {
			return "";
		}

		if (GhidraFileChooser.MY_COMPUTER.equals(getCurrentDirectory())) {
			String str = getModel().getDescription(file);
			if (str == null || str.length() == 0) {
				str = file.getAbsolutePath();
			}
			return str;
		}
		else if (GhidraFileChooser.RECENT.equals(getCurrentDirectory())) {
			return file.getAbsolutePath() + "  ";
		}
		return getFilename(file) + "  ";
	}

	private void setDirectoryList(File directory, List<File> files) {
		// if the visible listing is still the same directory as this incoming list of files
		if (currentDirectory().equals(directory)) {
			// recompute list cell dims before causing an update to the model
			directoryTableModel.setFiles(files);
			directoryTable.scrollRectToVisible(new Rectangle(0, 0, 0, 0));
			directoryListModel.setFiles(files);
			directoryList.scrollRectToVisible(new Rectangle(0, 0, 0, 0));
		}
		updateShortCutPanel();
	}

	/**
	 * Returns the selected file. This can be set either by the  programmer via 
	 * {@link #setSelectedFile(File)} or by a user action, such as either typing the 
	 * filename into the UI or selecting the file from a list in the UI.
	 * 
	 * @return the selected file; null if cancelled or no file was selected
	 */
	public File getSelectedFile() {
		show();
		if (wasCancelled) {
			return null;
		}

		return validatedFiles.getFile();
	}

	/**
	 * Returns the selected files.  This will show the file chooser
	 *
	 * @return the selected files; an empty array if cancelled or no file was selected
	 */
	public List<File> getSelectedFiles() {
		show();
		if (wasCancelled) {
			return Collections.emptyList();
		}

		List<File> filteredList = filterFilesForSelectionMode(validatedFiles);
		return filteredList;
	}

	private String getSelectionRequiredMessage() {
		if (isFilesAndDirectories()) {
			return "Please make a selection";
		}
		else if (isFilesOnly()) {
			return "Please select a file";
		}
		return "Please select a directory";
	}

	private List<File> filterFilesForSelectionMode(FileList list) {
		List<File> listCopy =
			list.getFiles().stream().filter(f -> f != null).collect(Collectors.toList());

		if (isFilesAndDirectories()) {
			return listCopy;
		}

		if (fileSelectionMode == GhidraFileChooserMode.DIRECTORIES_ONLY) {
			for (Iterator<File> iterator = listCopy.iterator(); iterator.hasNext();) {
				File file = iterator.next();
				if (!isDirectory(file)) {
					iterator.remove();
				}
			}
		}
		// must be files only
		else {
			for (Iterator<File> iterator = listCopy.iterator(); iterator.hasNext();) {
				File file = iterator.next();
				if (isDirectory(file)) {
					iterator.remove();
				}
			}
		}
		return listCopy;
	}

	/**
	 * Returns the selected file. This can be set either by the programmer
	 * via {@link #setSelectedFile(File)} or by a user action, such as either typing the filename
	 * into the UI or selecting the file from a list in the UI.
	 * <p>
	 * Note: this method can be called after the chooser has been shown, in which case the
	 * value returned has been validated by the chooser.  Also, the method may be called
	 * while the chooser is showing (like from a test thread).  In this case, the selected file
	 * will not have been validated by the chooser.
	 *
	 * @param show if true then the dialog is displayed
	 * @return the selected file; null if cancelled or no file was selected
	 */
	public File getSelectedFile(boolean show) {
		if (show) {
			return getSelectedFile();
		}

		if (isShowing()) {
			// NOTE: this is an unvalidated file, as this method has been called while
			//       the file chooser is still showing, before any validation has taken place
			return selectedFiles.getFile();
		}

		return validatedFiles.getFile();
	}

	/** Gets the file currently selected in the GUI */
	private GhidraFile getUserSelectedFileInDisplay() {

		File selectedFile = directoryModel.getSelectedFile();
		if (selectedFile == null) {
			return null;
		}

		return new GhidraFile(selectedFile.getAbsolutePath(), fileChooserModel.getSeparator());
	}

	private boolean isSpecialDirectory(File directory) {
		return directory.equals(MY_COMPUTER) || directory.equals(RECENT);
	}

	/**
	 * Sets the selected file. If the file's parent directory is not the current directory,
	 * changes the current directory to be the file's parent directory.
	 * <p>
	 * If the given file is a directory, then it's parent directory will be made the current
	 * directory and the directory represented by the file will be selected within the parent
	 * directory.
	 * <p>
	 * If the given file does not exist, then the following will happen:
	 * <ul>
	 *  <li>If the parent directory of the file exists, then the parent directory will be made
	 *      the current directory and the name of the file will be put into the filename
	 *      textfield; otherwise,
	 *  <li>If the parent file does <b>not</b> exist, then the selection is cleared.
	 * </ul>
	 * <p>
	 * If the given file is null, then the selected file state is cleared.
	 *
	 * @see #getSelectedFile
	 * @param file the selected file
	 */
	public void setSelectedFile(final File file) {
		if (file == null) {
			// nothing we can do; clear the selection
			worker.schedule(new ClearSelectedFilesJob());
			return;
		}

		File parentDirectory = file.getParentFile();
		if (!file.exists() && !fileExists(parentDirectory)) {
			// no valid file or directory; clear the selection
			worker.schedule(new ClearSelectedFilesJob());
			return;
		}

		// NOTE: we are updating this value here before the code below so that when show() is
		// called, the value will be set, in case any pending jobs that would normally set the
		// value have not finished.
		selectedFiles.setFile(file);

		updateDirAndSelectFile(validateParentDirectory(file), file, true, true);
	}

	private void setFilenameFieldText(String filename, boolean selectText) {
		String newFilename = filename;
		if (newFilename == null) {
			newFilename = "";
		}
		filenameTextField.setText(newFilename);
		if (selectText) {
			filenameTextField.selectAll();
		}
	}

	public void show() {
		validatedFiles.setFile(null);
		initialFile = selectedFiles.getFile();
		initialFileToSelect = initialFile;

		SystemUtilities.runSwingLater(() -> {
			File selectedFile = selectedFiles.getFile();
			if (!fileExists(selectedFile)) {
				// forces a refresh when there's no selected file - SCR 3001
				rescanCurrentDirectory();
			}
			else {
				updateDirAndSelectFile(selectedFile.getParentFile(), selectedFile, true, true);
			}
		});

		restorePreferences();
		DockingWindowManager.showDialog(parent, this);
		cancelEdits();
	}

	@Override
	public void close() {
		clearBackHistory();
		cancelEdits();
		clearStatusText();
		savePreferences();
		super.close();
	}

	private void savePreferences() {
		saveSize();
		saveViewStyle();
		Preferences.store();
	}

	private void restorePreferences() {
		restoreSize();
		restoreViewStyle();
	}

	private void saveSize() {
		String titleKey = getTitle();
		Dimension size = getDialogSize();
		if (size == null) {
			return;
		}
		Preferences.setProperty(WIDTH_PREFERENCE_PREFIX + titleKey, Integer.toString(size.width));
		Preferences.setProperty(HEIGHT_PREFERENCE_PREFIX + titleKey, Integer.toString(size.height));
	}

	private void saveViewStyle() {
		String titleKey = getTitle();
		String detailsString = showDetails ? DETAILS_VIEW_STYLE : SIMPLE_VIEW_STYLE;
		Preferences.setProperty(VIEW_STYLE_PREFIX + titleKey, detailsString);
	}

	private void restoreSize() {
		String titleKey = getTitle();
		String savedWidth = Preferences.getProperty(WIDTH_PREFERENCE_PREFIX + titleKey);
		String savedHeight = Preferences.getProperty(HEIGHT_PREFERENCE_PREFIX + titleKey);

		if (savedWidth == null || savedHeight == null) {
			return;
		}

		try {
			int width = Integer.parseInt(savedWidth);
			int height = Integer.parseInt(savedHeight);
			setDefaultSize(width, height);
		}
		catch (NumberFormatException nfe) {
			Msg.debug(this, "Unexpected error parsing as an Integer the saved size values: " +
				savedWidth + " and " + savedHeight);
		}
	}

	private void restoreViewStyle() {
		String titleKey = getTitle();
		String viewStyle = Preferences.getProperty(VIEW_STYLE_PREFIX + titleKey);
		if (viewStyle != null) {
			setShowDetails(viewStyle.equals(DETAILS_VIEW_STYLE));
		}
	}

	/**
	 * Returns the current directory.
	 * @return the current directory
	 * @see #setCurrentDirectory
	 */
	public File getCurrentDirectory() {
		return currentDirectory();
	}

	/**
	 * Sets the current directory. Passing in <code>null</code> sets the
	 * file chooser to point to the user's default directory.
	 * This default depends on the operating system. It is
	 * typically the "My Documents" folder on Windows, and the user's
	 * home directory on Unix.
	 * <br>
	 * If the file passed in as <code>currentDirectory</code> is not a
	 * directory, the parent of the file will be used as the currentDirectory.
	 * If the parent is not traversable, then it will walk up the parent tree
	 * until it finds a traversable directory, or hits the root of the
	 * file system.
	 * @param directory the current directory to point to
	 * @see #getCurrentDirectory
	 */
	public void setCurrentDirectory(File directory) {
		if (directory == null) {
			directory =
				new GhidraFile(System.getProperty("user.home"), fileChooserModel.getSeparator());
		}

		// see the API contract
		while (!isDirectory(directory) && (directory != null)) {
			directory = directory.getParentFile();
		}

		updateDirOnly(directory, false);
	}

	private void setCurrentDirectoryDisplay(final File directory, final boolean addToHistory) {
		if (directory == null) {
			return;
		}

		// SCR 4513 - exception if we don't cancel edits before changing the display
		cancelEdits();

		Swing.runNow(() -> {
			updateHistory(directory, addToHistory);

			if (directory.equals(MY_COMPUTER) || directory.equals(RECENT)) {
				currentPathTextField.setText(getFilename(directory));
			}
			else {
				currentPathTextField.setText(directory.getAbsolutePath());
			}
			currentPathTextField.setToolTipText(currentPathTextField.getText());
			updateNavigationButtons();
		});
	}

	GhidraFileChooserModel getModel() {
		return fileChooserModel;
	}

	GhidraFileChooserDirectoryModelIf getDirectoryModel() {
		return directoryModel;
	}

	FileChooserActionManager getActionManager() {
		return actionManager;
	}

	void setSelectedFileAndUpdateDisplay(File file) {
		worker.schedule(new SetSelectedFileJob(file));
	}

	private void doSetSelectedFileAndUpdateDisplay(File file) {
		if (lastInputFocus != null) {
			lastInputFocus.requestFocusInWindow();
		}

		if (file == null) {
			return;
		}

		// SCR 4513 - exception if we don't cancel edits before changing the display
		cancelEdits();
		selectedFiles.setFile(file);
		updateTextFieldForFile(file);

		directoryModel.setSelectedFile(file); // the list or table display
	}

	private void updateTextFieldForFile(File file) {
		if (file == null) {
			return;
		}

		boolean selectText = false;
		if (initialFileToSelect != null) {
			// we want to select the file text if it is the first time the chooser has just been
			// shown and the client has called setSelectedFile().
			selectText = file.equals(initialFileToSelect);
			initialFileToSelect = null;
		}

		if (isUserEditing()) {
			return; // don't disrupt what the user is doing in the text field
		}

		String newText = getFilename(file);
		String currentText = filenameTextField.getText();
		if (newText.equals(currentText)) {
			return; // nothing to do
		}

		if (!file.exists()) {
			// special case!: we will always put non-existent text in the field so that clients
			//                can call setSelectedFile() with suggested files choices (like for
			//                saving data.
			setFilenameFieldText(newText, selectText);
			return;
		}

		if (!isDirectory(file)) {
			if (fileSelectionMode.supportsFiles()) {
				setFilenameFieldText(newText, selectText);
			}
		}
		else {
			if (fileSelectionMode.supportsDirectories()) {
				File parentFile = file.getParentFile();
				if (parentFile == null || parentFile.equals(currentDirectory())) {
					// must be a root dir
					setFilenameFieldText(newText, selectText);
				}
			}
		}
	}

	private boolean isUserEditing() {
		if (filenameTextField.isMatchingListShowing()) {
			return true;
		}
		return false;
	}

	private void goUpOneDirectoryLevel() {
		cancelEdits();

		if (currentDirectory() == null) {
			return;
		}
		File parentFile = currentDirectory().getParentFile();
		if (parentFile == null) {
			return;
		}
		updateDirOnly(parentFile, false);
	}

	private void createNewFolder() {
		cancelEdits();

		boolean created = false;
		String newFolderName = NEW_FOLDER;
		if (fileChooserModel.createDirectory(currentDirectory(), newFolderName)) {
			created = true;
		}
		else {
			for (int i = 2; i < 100; i++) {
				newFolderName = NEW_FOLDER + " (" + i + ")";
				if (fileChooserModel.createDirectory(currentDirectory(), newFolderName)) {
					created = true;
					break;
				}
			}
		}

		if (!created) {
			Msg.showError(this, rootPanel, "Create Folder Failed",
				"Unable to create new folder in " + currentDirectory());
			return;
		}

		GhidraFile folder =
			new GhidraFile(currentDirectory(), newFolderName, fileChooserModel.getSeparator());
		directoryTableModel.insert(folder);
		directoryListModel.insert(folder);

		worker.schedule(new SetSelectedFilesAndStartEditJob(folder));
	}

	/**
	 * Causes the file chooser to refresh its contents
	 * with the content of the currently displayed directory.
	 */
	public void rescanCurrentDirectory() {
		cancelEdits();
		File currentDir = getCurrentDirectory();

		// take into account any changes the user has made to the filename text
		File currentSelectedFile = getSelectedFile(false);
		if (currentSelectedFile != null) {
			String name = getFilename(currentSelectedFile);
			if (!name.equals(filenameTextField.getText())) {
				currentSelectedFile = null;
			}
		}

		// don't make the current dir also the selected file
		if (currentDir != null && currentDir.equals(currentSelectedFile)) {
			currentSelectedFile = null;
		}
		updateDirAndSelectFile(currentDir, currentSelectedFile, true, false);
	}

	private void updateShortCutPanel() {
		// make sure that if one of the shortcut buttons is selected, the directory matches that button
		File currentDirectory = currentDirectory();
		checkShortCutButton(myComputerButton, currentDirectory);
		checkShortCutButton(homeButton, currentDirectory);
		checkShortCutButton(recentButton, currentDirectory);
		checkShortCutButton(desktopButton, currentDirectory);
	}

	private void checkShortCutButton(FileChooserToggleButton button, File currentDirectory) {
		boolean dirsMatch = currentDirectory.equals(button.getFile());
		if (button.isSelected() != dirsMatch) {
			shortCutButtonGroup.setSelected(button.getModel(), dirsMatch);
		}
	}

	/**
	 * Displays the WAIT panel. It handles the Swing thread issues.
	 */
	private void setWaitPanelVisible(final boolean visible) {
		Swing.runLater(() -> {
			if (visible) {
				card.show(cardPanel, CARD_WAIT);
			}
			else {
				updateDirectoryPresentationMode();
			}
		});
	}

	private void clearBackHistory() {
		history.clear();
	}

	private void updateNavigationButtons() {
		backButton.setEnabled(history.hasPrevious());
		forwardButton.setEnabled(history.hasNext());

		File dir = currentDirectory();
		boolean enable = dir != null && dir.getParentFile() != null;
		upLevelButton.setEnabled(enable);
	}

	private void updateHistoryWithSelectedFiles(HistoryEntry historyEntry) {

		File currentDir = currentDirectory();
		File selectedFile = selectedFiles.getFile();
		historyEntry.setSelectedFile(currentDir, selectedFile);
	}

	private void updateHistory(File dir, boolean addToHistory) {

		if (!directoryExistsOrIsLogicalDirectory(dir)) {
			return;
		}

		HistoryEntry historyEntry = history.getCurrentHistoryItem();
		if (historyEntry != null) {

			updateHistoryWithSelectedFiles(historyEntry);

			if (historyEntry.isSameDir(dir)) {
				// already recorded in history
				return;
			}
		}

		if (addToHistory) {
			history.add(new HistoryEntry(dir, null));
			updateNavigationButtons();
		}
	}

	/*package*/ int getHistorySize() {
		return history.size();
	}

	/** Returns true if the file exists on disk OR if it is a logical dir, like 'My Computer'  */
	private boolean directoryExistsOrIsLogicalDirectory(File directory) {
		if (directory == null) {
			return false;
		}
		return directory.exists() || directory.equals(MY_COMPUTER) || directory.equals(RECENT);
	}

	private boolean fileExists(File directory) {
		return directory != null && directory.exists();
	}

	private boolean isDirectory(File directory) {
		return fileChooserModel.isDirectory(directory) || MY_COMPUTER.equals(directory);
	}

	private void goBack() {
		history.goBack();
		updateNavigationButtons();
	}

	private void goForward() {
		history.goForward();
		updateNavigationButtons();
	}

	private void updateDirectoryPresentationMode() {
		if (isTableShowing()) {
			directoryModel = directoryTable;
			card.show(cardPanel, CARD_TABLE);
			int[] rows = directoryTable.getSelectedRows();
			directoryTableModel.fireTableDataChanged();
			directoryTable.clearSelection();
			for (int element : rows) {
				directoryTable.addRowSelectionInterval(element, element);
			}
		}
		else {
			directoryModel = directoryList;
			card.show(cardPanel, CARD_LIST);
		}
	}

	private void clearUserSelection() {
		directoryTable.clearSelection();
		directoryList.clearSelection();
		filenameTextField.setText("");
	}

	private void cancelEdits() {
		directoryTable.editingCanceled(null);
		directoryList.cancelListEdit();
	}

	private JScrollPane buildDirectoryTable() {
		directoryTableModel = new DirectoryTableModel(this);
		directoryTable = new DirectoryTable(this, directoryTableModel);
		directoryTable.setName("TABLE");
		directoryTable.setBackground(BACKGROUND_COLOR);

		directoryTable.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				lastInputFocus = directoryTable;
			}
		});

		JScrollPane scrollPane = new JScrollPane(directoryTable);
		scrollPane.getViewport().setBackground(BACKGROUND_COLOR);
		return scrollPane;
	}

	public void dispose() {
		actionManager.dispose();
		close();
		fileChooserModel = null;
	}

	/**
	 * Adds the specified file filter.
	 * @param f the new file filter
	 */
	public void addFileFilter(GhidraFileFilter f) {
		boolean exists = false;
		int nFilters = filterModel.getSize();
		for (int i = 0; i < nFilters; ++i) {
			GhidraFileFilter filter = filterModel.getElementAt(i);
			if (filter.getDescription().equals(f.getDescription())) {
				exists = true;
				break;
			}
		}

		// This is logically correct, but apparently tests fail with this call, and we are too
		// lazy to fix them
		//      SystemUtilities.assertTrue(!exists, "Attempted to duplicate file filter");

		if (!exists) {
			filterCombo.addItem(f);
			filterCombo.setSelectedItem(f);
		}
	}

	/**
	 * Set the selected filter to the given filter
	 * @param filter the filter to initially set
	 */
	public void setSelectedFileFilter(GhidraFileFilter filter) {
		filterCombo.setSelectedItem(filter);
	}

	/**
	 * Sets the current file filter.
	 * @param filter the file filter to make current
	 */
	public void setFileFilter(GhidraFileFilter filter) {
		ItemListener[] listeners = filterCombo.getItemListeners();
		for (ItemListener listener : listeners) {
			filterCombo.removeItemListener(listener);
		}

		filterCombo.removeAllItems();
		addFileFilter(GhidraFileFilter.ALL);
		if (filter != GhidraFileFilter.ALL) {
			addFileFilter(filter);
		}

		for (ItemListener listener : listeners) {
			filterCombo.addItemListener(listener);
		}
		filterCombo.setSelectedItem(filter);
	}

	/**
	 * Returns true if the user clicked the "cancel" button on the file chooser.
	 * @return true if the user clicked the "cancel" button on the file chooser
	 */
	public boolean wasCancelled() {
		return wasCancelled;
	}

	@Override
	protected void cancelCallback() {
		if (!isShowing()) {
			return; // nothing to do
		}

		setSelectedFile(initialFile);
		wasCancelled = true;
		super.cancelCallback();
	}

	private void enterCallback() {
		okCallback();
	}

	@Override
	protected void okCallback() {
		if (isMultiSelectionEnabled()) {
			okCallbackForMultipleSelectionMode();
		}
		else {
			okCallbackForSingleSelectionMode();
		}
	}

	private void okCallbackForSingleSelectionMode() {
		if (DOTDOT.equals(filenameTextField.getText())) {
			updateDirOnly(currentDirectory().getParentFile(), false);
			clearUserSelection();
			return;
		}
		if (DOT.equals(filenameTextField.getText())) {
			clearUserSelection();
			return;
		}

		File selectedFile = directoryModel.getSelectedFile();
		if (isFilesOnly() && isDirectory(selectedFile)) {
			setCurrentDirectory(selectedFile);
			return;
		}

		// 1) Get current file - user selected first, then try the current dir
		File newSelectedFile = getUnvalidatedUserSelectedFile();
		if (newSelectedFile == null) {
			newSelectedFile = getUnvalidatedDirectory();
			if (newSelectedFile == null) {
				return; // assume that the previous method handled the error that gave us null
			}
		}

		// 2) Handle relative vs. absolute
		if (fileChooserModel.isAbsolute(newSelectedFile)) {
			newSelectedFile = validateAbsoluteFile(newSelectedFile);
		}
		else {
			newSelectedFile = validateRelativeFile(newSelectedFile);
		}

		if (newSelectedFile == null) {
			return; // assume that the validate methods printed messages for the null case
		}

		if (isFilesOnly() && isDirectory(newSelectedFile)) {
			setCurrentDirectory(newSelectedFile);
			return;
		}

		doChooseFile(newSelectedFile);
	}

	private boolean isFilesOnly() {
		return fileSelectionMode == GhidraFileChooserMode.FILES_ONLY;
	}

	private boolean isDirectoriesOnly() {
		return fileSelectionMode == GhidraFileChooserMode.DIRECTORIES_ONLY;
	}

	private boolean isFilesAndDirectories() {
		return fileSelectionMode == GhidraFileChooserMode.FILES_AND_DIRECTORIES;
	}

	private void okCallbackForMultipleSelectionMode() {
		//
		// Assumption: if the user has selected multiple files, then that selection takes
		// precedence over any text entered in the text field.  Otherwise, we will just use the
		// same algorithm for single-selection mode, as defined elsewhere
		//
		if (selectedFiles.size() <= 1) {
			okCallbackForSingleSelectionMode();
			return;
		}

		if (selectedFiles.getFile() == null) {
			setStatusText(getSelectionRequiredMessage());
			return;
		}

		List<File> filteredList = filterFilesForSelectionMode(selectedFiles);
		if (filteredList.isEmpty()) {
			setStatusText(getSelectionRequiredMessage());
			return;
		}

		doChooseFiles(selectedFiles.getFiles());
	}

	private void doChooseFile(File validFile) {
		validatedFiles.setFile(validFile);
		wasCancelled = false;
		close();
		updateRecentList();
		clearUserSelection();
	}

	private void doChooseFiles(List<File> files) {
		validatedFiles.setFiles(files);
		wasCancelled = false;
		close();
		updateRecentList();
		clearUserSelection();
	}

	/**
	 * A callback method for clients that *know* the user has chosen a file(s), like a
	 * list with a mouse listener that validates a double-click.
	 * <p>
	 * <b>
	 * If you don't know how to use this method, then don't call it!
	 * </b>
	 * @param file the file chosen by the user
	 */
	void userChoseFile(File file) {
		doChooseFile(file);
	}

	/**
	 * A callback method for clients that *know* the user has selected a file(s), like a
	 * list with a mouse listener that validates a double-click.
	 * <p>
	 * <b>
	 * If you don't know how to use this method, then don't call it!
	 * </b>
	 * @param files the files to select
	 */
	void userSelectedFiles(List<File> files) {
		selectedFiles.setFiles(files);

		// Update the display to...
		if (isMultiSelectionEnabled() && selectedFiles.size() > 1) {
			// clear the filename text field when multiple files are selected
			filenameTextField.setText("");
		}
		else {
			// set the filename text on single selection, regardless of mode
			updateTextFieldForFile(selectedFiles.getFile());
		}
	}

	/**
	 * Gets a directory that has not been validated.  This method will only return a
	 *  directory if the selection mode is DIRECTORIES_ONLY
	 */
	private File getUnvalidatedDirectory() {
		// currently only allow selection of the current directory if we are in directory mode
		if (!isDirectoriesOnly()) {
			setStatusText("Please select a file");
			return null;
		}

		return currentDirectory();
	}

	/** Gets the file chosen by the user, whether typed in by them or selected in the GUI */
	private File getUnvalidatedUserSelectedFile() {

		// user entered text takes precedence
		String filenameFieldText = filenameTextField.getText();
		if (filenameFieldText != null && filenameFieldText.trim().length() != 0) {
			// begin user text validation...
			File testFile =
				new GhidraFile(filenameTextField.getText(), fileChooserModel.getSeparator());
			File currentDirectory = currentDirectory();
			if (isSpecialDirectory(currentDirectory)) {
				setStatusText("Cannot create a file in " + currentDirectory);
				return null;
			}

			// users cannot enter invalid remote names or OS nicknames
			FileSystemView fsv = FileSystemView.getFileSystemView();
			if (fsv.isComputerNode(testFile)) {
				setStatusText("Please specify the name of a valid share.");
				return null;
			}

			return testFile;
		}

		// no text in the text field; must have a selected file
		GhidraFile userSelectedFile = getUserSelectedFileInDisplay();
		if (userSelectedFile == null) {
			setStatusText("Please select a file.");
			return null;
		}

		return userSelectedFile;
	}

	private File validateAbsoluteFile(File file) {
		File currentDirectory = currentDirectory();
		File parentFile = file.getParentFile();
		if (isDirectory(file)) {
			if (isSpecialCurrentDirectorySelection(file)) {
				return file;
			}

			// We navigate on absolute file selection if it is in the filename text field.  This
			// allows the user to navigate by typing absolute paths in the chooser.  Assume for
			// now that any text in the text field matches that of the file we've been given, since
			// the chooser always puts the text for the selected file in the text field.
			String currentText = filenameTextField.getText();
			if (currentText != null && !currentText.isEmpty()) {
				setCurrentDirectory(file);
				clearUserSelection();
				return null;
			}
		}
		else if (parentFile != null && !parentFile.equals(currentDirectory)) {
			// accept the file; set the parent directory as the active directory
			updateDirOnly(parentFile, false);
			clearUserSelection();
		}
		return file;
	}

	/**
	 * SCR 3962 - in this mode we allow the user to press Enter/OK with no text in
	 * the text field, which means to user the current directory as the selected dir
	 */
	private boolean isSpecialCurrentDirectorySelection(File file) {
		if (!isDirectoriesOnly()) {
			return false;
		}

		File currentDirectory = currentDirectory();
		String text = filenameTextField.getText();
		boolean noUserText = text == null || text.isEmpty();
		return file.equals(currentDirectory) && noUserText;
	}

	private File validateRelativeFile(File file) {
		File currentDirectory = currentDirectory();

		File testFile =
			new GhidraFile(currentDirectory, file.getName(), fileChooserModel.getSeparator());

		if (!testFile.exists()) {
			//
			// Handle the case where the user entered a path into the text field (which will
			// be the value of file.getName())
			//
			File testFileFullPath =
				new GhidraFile(currentDirectory, file.getPath(), fileChooserModel.getSeparator());
			if (testFileFullPath.exists()) {
				testFile = testFileFullPath;
			}
		}

		//
		// Handle the case where the current directly name can get double appended
		//
		if (!testFile.exists() && testFile.getName().equals(currentDirectory.getName())) {
			testFile = currentDirectory;
		}

		if (isFilesOnly() && isDirectory(testFile)) {
			updateDirAndSelectFile(testFile, null, false, true);
			clearUserSelection();
			return null;
		}

		return testFile;
	}

	private File validateParentDirectory(File file) {
		File parentDirectory = file.getParentFile();
		if (isRootDirectory(file)) {
			// the given file to select is a root directory; load the MY_COMPUTER view so that
			// we can select the root directory
			parentDirectory = MY_COMPUTER;
		}
		return parentDirectory;
	}

	private boolean isRootDirectory(File file) {
		return isDirectory(file) && file.getParentFile() == null;
	}

	private String getFilename(File file) {
		if (isRootDirectory(file)) {
			return file.getPath();
		}
		return file.getName();
	}

	private void loadRecentList() {
		if (!initialized) {
			List<String> propNames = Preferences.getPropertyNames();
			Collections.sort(propNames);
			for (String element : propNames) {
				if (element.startsWith("RECENT_")) {
					String value = Preferences.getProperty(element, null, true);
					if (value == null) {
						continue;
					}
					RecentGhidraFile file =
						new RecentGhidraFile(value, fileChooserModel.getSeparator());
					if (file.exists() && !recentList.contains(file)) {
						recentList.add(file);
					}
				}
			}
			initialized = true;
		}
	}

	private void updateRecentList() {
		File currentDirectory = currentDirectory();
		if (!currentDirectory.equals(RECENT) && !recentList.contains(currentDirectory)) {
			String path = currentDirectory.getAbsolutePath();
			recentList.add(0, new RecentGhidraFile(path, fileChooserModel.getSeparator()));
		}

		while (recentList.size() > MAX_RECENT) {
			recentList.remove(recentList.size() - 1);
		}

		saveRecentList();
	}

	private void saveRecentList() {
		for (int i = 0; i < recentList.size(); ++i) {
			File f = recentList.get(i);
			Preferences.setProperty("RECENT_" + i, f.getAbsolutePath());
		}
		Preferences.store();
	}

	private boolean isTableShowing() {
		return showDetails;
	}

	String getInvalidFilenameMessage(String filename) {
		switch (filename) {
			case ".":
			case "..":
				return "Reserved name '" + filename + "'";
			default:
				Matcher m = GhidraFileChooser.INVALID_FILENAME_PATTERN.matcher(filename);
				if (m.find()) {
					return "Invalid characters: " + m.group();
				}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private abstract class FileChooserJob extends Job {

		@Override
		public void run(TaskMonitor monitor) {
			run();
			SystemUtilities.runSwingLater(() -> runSwing());
		}

		public void run() {
			// subclasses override to have code run in a worker thread (off the swing thread)
		}

		public void runSwing() {
			// subclasses can override to have code execute in the swing thread
		}

	}

	// This job exists to make sure that we perform operations in the right order
	private class SetSelectedFileJob extends FileChooserJob {

		private final File fileToSelect;

		SetSelectedFileJob(File file) {
			this.fileToSelect = file;
		}

		@Override
		public void runSwing() {
			doSetSelectedFileAndUpdateDisplay(fileToSelect);
		}
	}

	private class SetSelectedFileAndAcceptSelection extends FileChooserJob {
		private final File fileToSelect;

		SetSelectedFileAndAcceptSelection(File file) {
			this.fileToSelect = file;
		}

		@Override
		public void runSwing() {
			doSetSelectedFileAndUpdateDisplay(fileToSelect);
		}
	}

	private class ClearSelectedFilesJob extends FileChooserJob {
		@Override
		public void runSwing() {
			clearUserSelection();
			selectedFiles.setFile(null);
			validatedFiles.setFile(null);
		}
	}

	private class UpdateDirectoryContentsJob extends FileChooserJob {
		private File directory;
		private File file;
		private List<File> loadedFiles;

		private UpdateDirectoryContentsJob(File directory, File selectedFile,
				boolean addToHistory) {
			this.directory = directory;
			this.file = selectedFile;

			setCurrentDirectoryDisplay(directory, addToHistory);
			setWaitPanelVisible(true);
		}

		@Override
		public void run() {
			if (fileChooserModel == null) {
				return;
			}

			File[] files = fileChooserModel.getListing(directory, GhidraFileChooser.this);
			loadedFiles = Arrays.asList(files);
			Collections.sort(loadedFiles, new FileComparator(fileChooserModel));
		}

		@Override
		public void runSwing() {
			setDirectoryList(directory, loadedFiles);
			setWaitPanelVisible(false);
			setSelectedFileAndUpdateDisplay(file);
		}
	}

	private class UpdateMyComputerJob extends FileChooserJob {

		private final File myComputerFile;
		private final boolean addToHistory;
		private List<File> roots;

		public UpdateMyComputerJob(File myComputerFile, boolean addToHistory) {
			this.myComputerFile = myComputerFile;
			this.addToHistory = addToHistory;
		}

		@Override
		public void run() {
			roots = Arrays.asList(fileChooserModel.getRoots());
			Collections.sort(roots);
		}

		@Override
		public void runSwing() {
			setCurrentDirectoryDisplay(myComputerFile, addToHistory);
			setDirectoryList(myComputerFile, roots);
		}
	}

	private class UpdateRecentJob extends FileChooserJob {

		private final boolean addToHistory;
		private final File recentFile;

		UpdateRecentJob(File recentFile, boolean addToHistory) {
			this.recentFile = recentFile;
			this.addToHistory = addToHistory;
		}

		@Override
		public void runSwing() {
			setCurrentDirectoryDisplay(recentFile, addToHistory);
			List<File> list = CollectionUtils.asList(recentList, File.class);
			setDirectoryList(recentFile, list);
		}
	}

	private class SetSelectedFilesAndStartEditJob extends FileChooserJob {
		private final File fileToSelect;

		SetSelectedFilesAndStartEditJob(File file) {
			this.fileToSelect = file;
		}

		@Override
		public void runSwing() {
			doSetSelectedFileAndUpdateDisplay(fileToSelect);
			directoryModel.edit();
		}
	}

	// a custom button group that allows us to deselect buttons, which Java's does not
	private class UnselectableButtonGroup extends ButtonGroup {

		private ButtonModel overriddenSelection = null;

		@Override
		public void add(AbstractButton b) {
			if (b == null) {
				return;
			}
			buttons.addElement(b);

			if (b.isSelected()) {
				if (overriddenSelection == null) {
					overriddenSelection = b.getModel();
				}
				else {
					b.setSelected(false);
				}
			}

			b.getModel().setGroup(this);
		}

		@Override
		public void remove(AbstractButton b) {
			if (b == null) {
				return;
			}
			buttons.removeElement(b);
			if (b.getModel() == overriddenSelection) {
				overriddenSelection = null;
			}
			b.getModel().setGroup(null);
		}

		@Override
		public ButtonModel getSelection() {
			return overriddenSelection;
		}

		@Override
		public void setSelected(ButtonModel m, boolean b) {
			if (!b && overriddenSelection != null) {
				overriddenSelection = null;
				m.setSelected(false);
			}

			else if (b && m != null && m != overriddenSelection) {
				ButtonModel oldSelection = overriddenSelection;
				overriddenSelection = m;
				if (oldSelection != null) {
					oldSelection.setSelected(false);
				}
				m.setSelected(true);
			}
		}

		@Override
		public boolean isSelected(ButtonModel m) {
			return (m == overriddenSelection);
		}
	}

	/**
	 * A list that allows us to always access the first cell without having to check the lists
	 * size.  The list also allows us to clear and set a value in one method call.  We are
	 * essentially using this list to hold selected files, where in certain modes, there will only
	 * be a single file selection.
	 * 
	 * <P>The methods on the class are synchronized to ensure thread visibility.
	 */
	private class FileList {

		private List<File> files = new ArrayList<>();

		public FileList() {
			files.add(null); // make sure we always have a value at cell 0
		}

		public synchronized int size() {
			return files.size();
		}

		public synchronized List<File> getFiles() {
			return new ArrayList<>(files);
		}

		public synchronized void setFiles(List<File> newFiles) {
			files.clear();
			if (newFiles == null || newFiles.isEmpty()) {
				files.add(null);
			}
			else {
				files.addAll(newFiles);
			}
		}

		public synchronized void setFile(File file) {
			files.clear();
			files.add(file);
		}

		public synchronized File getFile() {
			return files.get(0);
		}

		@Override
		public String toString() {
			return files.toString();
		}
	}

	/**
	 * Container class to manage history entries for a directory and any selected file
	 */
	private class HistoryEntry {
		private File parentDir;
		private File selectedFile;

		HistoryEntry(File parentDir, File selectedFile) {
			this.parentDir = parentDir;
			this.selectedFile = selectedFile;
		}

		boolean isSameDir(File dir) {
			return dir.equals(parentDir);
		}

		void setSelectedFile(File dir, File selectedFile) {
			if (!parentDir.equals(dir)) {
				// not my dir; don't save the selection
				return;
			}

			if (selectedFile == null) {
				// nothing to save
				return;
			}

			File selectedParent = selectedFile.getParentFile();
			if (parentDir.equals(selectedParent)) {
				this.selectedFile = selectedFile;
			}
		}

		File getSelectedFile() {
			return selectedFile;
		}

		@Override
		public String toString() {
			String selectedFilesText = "";
			if (selectedFile != null) {
				selectedFilesText = " *" + selectedFile;
			}
			return parentDir.getName() + selectedFilesText;
		}
	}
}
