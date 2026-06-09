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
package docking.widgets;

import java.awt.*;
import java.awt.event.*;
import java.awt.font.FontRenderContext;
import java.awt.font.GlyphVector;
import java.awt.geom.Rectangle2D;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.*;
import javax.swing.text.Caret;

import org.apache.commons.lang3.StringUtils;

import docking.DockingWindowManager;
import docking.widgets.DropDownTextFieldDataModel.SearchMode;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.list.GList;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.GThemeDefaults.Colors.Messages;
import generic.theme.GThemeDefaults.Colors.Tooltips;
import generic.util.WindowUtilities;
import ghidra.framework.options.PreferenceState;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.task.SwingUpdateManager;
import help.Help;
import help.HelpService;
import util.CollectionUtils;

/**
 * A text field that handles comparing text typed by the user to the list of objects and then
 * presenting potential matches in a drop down window.  The items in this window cannot be selected.
 *
 * <P>This class will fire {@link #fireEditingStopped()} and {@link #fireEditingCancelled()} events
 * when the user makes a choice by pressing the ENTER key, thus allowing the client code to use
 * this class similar in fashion to a property editor.  This behavior can be configured to:
 * <UL>
 * 	<LI>Not consume the ENTER key press (it consumes by default), allowing the parent container
 *      to process the event (see {@link #setConsumeEnterKeyPress(boolean)}
 *  </LI>
 *  <LI>Ignore the ENTER key press completely (see {@link #setIgnoreEnterKeyPress(boolean)}
 *  </LI>
 * </UL>
 *
 * <p>This class is subclassed to not only have the matching behavior, but to also allow for user
 * selections.
 *
 * @param <T> The type of object that this model manipulates
 */
public class DropDownTextField<T> extends JTextField implements GComponent {

	private static final Cursor CURSOR_HAND = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
	private static final Cursor CURSOR_DEFAULT = Cursor.getDefaultCursor();
	private static final int DEFAULT_MAX_UPDATE_DELAY = 2000;
	private static final int MIN_HEIGHT = 300;
	private static final int MIN_WIDTH = 200;
	protected static final Color PREVIEW_WINDOW_BGCOLOR = Tooltips.BACKGROUND;
	protected static final Color PREVIEW_WINDOW_FGCOLOR = Tooltips.FOREGROUND;

	private JWindow toolTipWindow; // delayed initialization for parenting
	private JWindow matchingWindow; // delayed initialization for parenting
	private DropDownWindowVisibilityListener<T> windowVisibilityListener =
		new DropDownWindowVisibilityListener<>();

	private GDHtmlLabel previewLabel;
	protected DropDownList list = new DropDownList();

	private WeakSet<DropDownSelectionChoiceListener<T>> choiceListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	private Collection<CellEditorListener> cellEditorListeners = new HashSet<>();
	private DocumentListener documentListener = new UpdateDocumentListener();
	private CaretListener caretListener = new UpdateCaretListener();
	private InternalKeyListener keyListener = new InternalKeyListener();
	private WindowComponentListener parentWindowListener = new WindowComponentListener();
	private T selectedValue;

	private int matchingWindowHeight = MIN_HEIGHT;
	private Point lastLocation;
	protected final DropDownTextFieldDataModel<T> dataModel;

	protected boolean internallyDrivenUpdate;
	private boolean consumeEnterKeyPress = true; // consume Enter presses by default
	private boolean ignoreEnterKeyPress = false; // do not ignore enter by default
	private boolean textFieldNotFocused;
	private boolean showMachingListOnEmptyText;

	// We use an update manager to buffer requests to update the matches.  This allows us to be
	// more responsive when the user is attempting to type multiple characters
	private String pendingTextUpdate;
	private SwingUpdateManager updateManager;

	/**
	 * The text that was used to generate the current list of matches.  This can be different than
	 * the text of this text field, as the user can move the cursor around, which will change the
	 * list of matches.  Also, we can set the value of the text field as the user arrows through
	 * the list, which will change the contents of the text field, but not the list of matches.
	 */
	private String currentMatchingText;

	/**
	 * Search mode support.  Clients specify search modes that allow the user to change how results
	 * are matched. For backward compatibility, this will be empty for clients that have not 
	 * specified search modes.
	 */
	private List<SearchMode> searchModes = new ArrayList<>();
	private boolean searchModeIsHovered;
	private SearchMode searchMode = SearchMode.UNKNOWN;
	private SearchModeBounds searchModeBounds;

	/**
	* Constructor.
	* <p>
	* Uses the default refresh delay of 350ms.
	*
	* @param dataModel provides element storage and search capabilities to this component.
	*/
	public DropDownTextField(DropDownTextFieldDataModel<T> dataModel) {
		this(dataModel, 350);
	}

	/**
	 * Constructor.
	 *
	 * @param dataModel provides element storage and search capabilities to this component.
	 * @param updateMinDelay suggestion list refresh delay, triggered after search results have
	 * changed. Too low a value may cause an inconsistent view as filtering tasks complete; too
	 * high a value delivers an unresponsive user experience.
	 */
	public DropDownTextField(DropDownTextFieldDataModel<T> dataModel, int updateMinDelay) {
		super(30);
		this.dataModel = dataModel;

		init(updateMinDelay);
	}

	@Override
	public void updateUI() {

		// reset the hint bounds; this value is based on the current font
		searchModeBounds = null;

		super.updateUI();
	}

	private void init(int updateMinDelay) {

		List<SearchMode> modes = dataModel.getSupportedSearchModes();
		for (SearchMode mode : modes) {
			if (mode != SearchMode.UNKNOWN && !searchModes.contains(mode)) {
				searchModes.add(mode);

				// pick the first mode to use
				if (searchMode == SearchMode.UNKNOWN) {
					searchMode = mode;
				}
			}
		}

		installSearchModeDisplay();

		// add a one-time listener to this field to restore any saved state, like the search mode
		DockingWindowManager.registerComponentLoadedListener(this, (dwm, provider) -> {
			loadPreferenceState();
		});

		updateManager = new SwingUpdateManager(updateMinDelay, DEFAULT_MAX_UPDATE_DELAY,
			"Drop Down Selection Text Field Update Manager", () -> {
				if (pendingTextUpdate == null) {
					return; // not sure if this can happen
				}
				doUpdateDisplayContents(pendingTextUpdate);
				pendingTextUpdate = null;
			});

		addFocusListener(new HideWindowFocusListener());

		// key listeners for hiding matching window
		addKeyListener(keyListener);

		setPreviewPaneAttributes();
		initDataList();

		getAccessibleContext().setAccessibleName("Data Type Editor");

		HelpService help = Help.getHelpService();
		help.registerDynamicHelp(this, new SearchModeHelpLocation());
	}

	private void installSearchModeDisplay() {

		if (!hasMultipleSearchModes()) {
			return;
		}

		addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				// when resized, update the location of the search mode hint when we get repainted
				searchModeBounds = null;
			}
		});

		SearchModeMouseListener mouseListener = new SearchModeMouseListener();
		addMouseMotionListener(mouseListener);
		addMouseListener(mouseListener);
	}

	private boolean hasMultipleSearchModes() {
		return searchModes.size() > 1;
	}

	private boolean isOverSearchMode(MouseEvent e) {
		if (searchModeBounds == null) {
			return false; // have not yet been painted
		}

		Point p = e.getPoint();
		return searchModeBounds.isHovered(p);
	}

	public SearchMode getSearchMode() {
		return searchMode;
	}

	public void setSearchMode(SearchMode newMode) {

		if (!searchModes.contains(newMode)) {
			throw new IllegalArgumentException(
				"Search mode is not supported by this texts field: " + newMode);
		}
		doSetSearchMode(newMode);
	}

	private void doSetSearchMode(SearchMode newMode) {
		searchMode = newMode;
		searchModeBounds = null;
		repaint();

		savePreferenceState();

		maybeUpdateDisplayContents(true);
	}

	private void toggleSearchMode(boolean forward) {

		if (!hasMultipleSearchModes()) {
			return;
		}

		int index = searchModes.indexOf(searchMode);
		int next = forward ? index + 1 : index - 1;
		if (forward) {
			if (next == searchModes.size()) {
				next = 0;
			}
		}
		else {
			if (next == -1) {
				next = searchModes.size() - 1;
			}
		}

		SearchMode newMode = searchModes.get(next);
		doSetSearchMode(newMode);
	}

	private void savePreferenceState() {

		String preferenceKey = dataModel.getClass().getSimpleName();
		PreferenceState state = new PreferenceState();
		state.putEnum("searchMode", searchMode);

		// We are in the UI at this point, so we have a valid window manager.  (The window manager 
		// may be null in testing.)
		DockingWindowManager dwm = DockingWindowManager.getInstance(this);
		if (dwm != null) {
			dwm.putPreferenceState(preferenceKey, state);
		}
	}

	private void loadPreferenceState() {
		String preferenceKey = dataModel.getClass().getSimpleName();

		// We are in the UI at this point, so we have a valid window manager.  (The window manager 
		// may be null in testing.)
		DockingWindowManager dwm = DockingWindowManager.getInstance(this);
		if (dwm == null) {
			return;
		}

		PreferenceState state = dwm.getPreferenceState(preferenceKey);
		if (state == null) {
			return;
		}

		searchMode = state.getEnum("searchMode", searchMode);
		searchModeBounds = null;
		repaint();
	}

	protected ListSelectionModel createListSelectionModel() {
		return new NoSelectionAllowedListSelectionModel();
	}

	protected void setPreviewPaneAttributes() {
		previewLabel = new GDHtmlLabel();
		previewLabel.setOpaque(true);
		previewLabel.setBackground(PREVIEW_WINDOW_BGCOLOR);
		previewLabel.setForeground(PREVIEW_WINDOW_FGCOLOR);
		previewLabel.setVerticalAlignment(SwingConstants.TOP);
		previewLabel.setFocusable(false);
	}

	protected void setSelectedItems() {
		if (selectedValue != null) {
			list.setSelectedValue(selectedValue, true);
		}
	}

	protected ListSelectionListener getPreviewListener() {
		return new PreviewListener();
	}

	protected JComponent getPreviewPaneComponent() {
		return previewLabel;
	}

	private void validateChosenItemAgainstText(boolean isListShowing) {
		//
		// If the text differs from that of the chosen item, then the implication is the user has
		// changed the text after the last time an item was chosen and after the drop-down list was
		// closed (if they haven't changed the text, then it will have been set to the value of the
		// currently selected item).  The user will do this if they want a new item that is not in
		// the list, but the new item starts with the same value as something that is in the list.
		//
		if (selectedValue == null) {
			return; // nothing to validate
		}

		String selectedValueText = dataModel.getDisplayText(selectedValue);
		String textFieldText = getText();
		if (textFieldText == null || textFieldText.isEmpty()) {
			return; // no text to validate against
		}

		// clear the value if the text is different (unless it starts with the selected value,
		// which implies the user had added some text, like a '*' character
		if (!selectedValueText.equals(textFieldText) &&
			!textFieldText.startsWith(selectedValueText)) {
			selectedValue = null; // the user has changed the text
		}
	}

	private void initDataList() {

		list.setCellRenderer(dataModel.getListRenderer());

		list.addKeyListener(keyListener);
		list.setFocusable(false);
		list.setSelectionModel(createListSelectionModel());

		// add selection listeners to the list to be notified of user selections and
		// to commit the data
		list.addMouseListener(new ListSelectionMouseListener());

		// updates the tooltip text window
		list.addListSelectionListener(getPreviewListener());
	}

	private void addUpdateListeners() {
		removeUpdateListeners(); // prevents accidental double adding of listeners
		addCaretListener(caretListener);
		getDocument().addDocumentListener(documentListener);
	}

	private void removeUpdateListeners() {
		removeCaretListener(caretListener);
		getDocument().removeDocumentListener(documentListener);
	}

	/**
	 * Overridden to allow for the setting of text without showing the completion window.  This
	 * is useful for setting the current value to be edited before the using initiates editing.
	 *
	 * @param text The text to set on this text field.
	 */
	@Override
	public void setText(String text) {
		hideMatchingWindow();

		// this series of calls prevents the completion window from showing when setting text
		// Note: the window will be recreated and the listeners will be added when editing is
		// initiated
		matchingWindow = null;
		removeUpdateListeners(); // these will be added again later when the window is re-created
		super.setText(text);
		selectAll();
	}

	protected void setTextWithoutClosingCompletionWindow(String text) {
		super.setText(text);
	}

	private void updateDisplayLocation(boolean hasMatches) {
		if (!hasMatches) {
			hideMatchingWindow();
			return;
		}

		if (isShowing()) {
			updateWindowLocation();
			showMatchingWindow();

			JComponent previewComponent = getPreviewPaneComponent();
			previewComponent.setBackground(PREVIEW_WINDOW_BGCOLOR);
			previewComponent.setForeground(PREVIEW_WINDOW_FGCOLOR);
			toolTipWindow.setVisible(hasPreview());
		}
	}

	protected boolean hasPreview() {
		return !StringUtils.isBlank(previewLabel.getText());
	}

	private void updateWindowLocation() {
		Point location = getLocationOnScreen();
		if (location.equals(lastLocation)) {
			return;
		}

		lastLocation = new Point(location.x, location.y + getHeight());
		Rectangle newBounds = new Rectangle(lastLocation.x, lastLocation.y,
			Math.max(MIN_WIDTH, getWidth()), matchingWindowHeight);

		list.setFixedCellWidth(newBounds.width - 20); // add some fudge for scrollbars

		getMatchingWindow().setBounds(newBounds);

		toolTipWindow.setBounds(newBounds.x + newBounds.width, newBounds.y, newBounds.width,
			newBounds.height);
	}

	private void updateDisplayContents(String userText) {
		pendingTextUpdate = userText;
		updateManager.updateLater();
	}

	private void maybeUpdateDisplayContents(boolean force) {
		if (textFieldNotFocused) {
			return;
		}

		String text = getText();
		if (StringUtils.isBlank(text)) {
			return;
		}

		// caret position only matters with 'starts with', as the user can arrow through the text
		// to change which text the 'starts with' matches
		if (!isStartsWithSearch()) {
			if (force || isDifferentText(text)) {
				updateDisplayContents(text);
			}
			return;
		}

		Caret caret = getCaret();
		int dot = caret.getDot();
		String textToCaret = text.substring(0, dot);
		if (force || isDifferentText(textToCaret)) {
			updateDisplayContents(textToCaret);
		}
	}

	private boolean isDifferentText(String newText) {
		return !CollectionUtils.isOneOf(newText, currentMatchingText, pendingTextUpdate);
	}

	private boolean isStartsWithSearch() {
		if (hasMultipleSearchModes()) {
			return searchMode == SearchMode.STARTS_WITH;
		}

		return searchMode == SearchMode.STARTS_WITH ||
			searchMode == SearchMode.UNKNOWN; // backward compatibility 
	}

	private void doUpdateDisplayContents(String userText) {
		if (internallyDrivenUpdate) {
			internallyDrivenUpdate = false;
			return;
		}

		currentMatchingText = userText;
		List<T> data = getMatchingData(userText);

		// use a custom model here so that we don't create a copy of the data
		list.setModel(new AbstractListModel<T>() {
			@Override
			public int getSize() {
				return data.size();
			}

			@Override
			public T getElementAt(int i) {
				return data.get(i);
			}
		});

		// adjust the display based upon the list contents
		if (data.isEmpty()) {
			updateDisplayLocation(false);
			return;
		}

		setSelectedItems();

		int index = dataModel.getIndexOfFirstMatchingEntry(data, userText);
		if (index < 0) {
			// make sure that something is selected
			list.setSelectedIndex(0);
			list.ensureIndexIsVisible(0);
		}
		else {
			list.setSelectedIndex(index);
			list.ensureIndexIsVisible(index);
		}

		updateDisplayLocation(true);
	}

	// for testing so that we can override, otherwise would be private
	protected List<T> getMatchingData(String searchText) {
		if (searchText == null) {
			return Collections.emptyList();
		}

		// By default we do not show the matches list is empty.  This seems less noisy.  Some  
		// clients would rather have empty text show all available choices.
		if (searchText.isEmpty() && !showMachingListOnEmptyText) {
			return Collections.emptyList();
		}

		// get the sublist of matches--this may take a while
		Cursor previousCursor = getCursor();
		try {
			setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

			if (searchMode == SearchMode.UNKNOWN) {
				// backward compatible
				return dataModel.getMatchingData(searchText);
			}
			return dataModel.getMatchingData(searchText, searchMode);

		}
		finally {
			setCursor(previousCursor);
		}
	}

	public boolean isMatchingListShowing() {
		if (matchingWindow == null) {
			return false;
		}
		return matchingWindow.isShowing();
	}

	/**
	 * Shows the matching list.  This can be used to show all data when the user has not typed any
	 * text.  For data models that have large data sets, this call may not show the matching list.
	 * This behavior is determine by the current data model.
	 */
	public void showMatchingList() {

		//
		// We temporarily enable this list to show for empty text, even if the text is not empty.
		// This handles the default setting, which has this feature off.  We can refactor this class
		// to allow us to make a direct call instead of using this temporary setting.  This seems
		// simple enough for now.
		//
		boolean restore = showMachingListOnEmptyText;
		try {
			showMachingListOnEmptyText = true;
			pendingTextUpdate = pendingTextUpdate != null ? pendingTextUpdate : getText();
			updateManager.updateNow();
		}
		finally {
			showMachingListOnEmptyText = restore;
		}
	}

	/**
	 * When true, this field will not pass Enter key press events up to it's parent <b>when the
	 * drop-down selection window is open</b>.  However, an Enter key press will still be
	 * "unconsumed" when the drop-down window is not open. When set to false, this method will
	 * always pass the Enter key press up to it's parent.
	 *
	 * <P>The default is true.  Clients will set this to false when they wish to respond to an
	 * Enter event.  For example, a dialog may want to close itself on an Enter key press, even
	 * when the drop-down selection text field is still open. Contrastingly, when this field is
	 * embedded inside of a larger editor, like a multi-editor field dialog, the Enter key press
	 * should simply trigger the drop-down window to close and the editing to stop, but should not
	 * trigger the overall dialog to close.
	 * @param consume true to consume
	 *
	 */
	public void setConsumeEnterKeyPress(boolean consume) {
		this.consumeEnterKeyPress = consume;
	}

	/**
	 * True signals to do nothing when the user presses Enter.  The default is to respond to the
	 * Enter key, using any existing selection to set this field's {@link #getSelectedValue()
	 * selected value}.
	 *
	 * <P>This can be set to true to allow clients to show drop-down matches without allowing the
	 * user to select them, triggering the window to be closed.
	 *
	 * @param ignore true to ignore Enter presses; false is the default
	 */
	public void setIgnoreEnterKeyPress(boolean ignore) {
		this.ignoreEnterKeyPress = ignore;
	}

	/**
	 * Allows this text field to show all potential matches when the text of the field is empty.
	 * The default is false.
	 * @param show true to allow the list to be shown
	 */
	public void setShowMatchingListOnEmptyText(boolean show) {
		this.showMachingListOnEmptyText = show;
	}

	/**
	 * Sets the height of the matching window.  The default value is {@value #MIN_HEIGHT}.
	 *
	 * @param height the new height
	 */
	public void setMatchingWindowHeight(int height) {
		matchingWindowHeight = height;
		if (matchingWindow == null) {
			return; // we have not yet been initialized; the changes will be picked-up later
		}

		// the window exists, update its size
		updateDisplayLocation(getMatchingWindow().isShowing());
	}

	/**
	 * Adds a listener that will be called back when the user makes a choice from the drop-down
	 * list.  A choice is a user action that triggers the selection window to be closed and updates
	 * the text field.
	 *
	 * <P>Note: the listener is stored in a {@link WeakDataStructureFactory weak data structure},
	 * so you must maintain a reference to the listener you pass in--anonymous classes or lambdas
	 * will not work.
	 *
	 * @param listener the listener
	 */
	public void addDropDownSelectionChoiceListener(DropDownSelectionChoiceListener<T> listener) {
		choiceListeners.add(listener);
	}

	/**
	 * Adds a listener to be notified when cell editing is canceled or completed.
	 * @param listener The listener to add
	 * @throws IllegalArgumentException if the listener has already been added
	 */
	public void addCellEditorListener(CellEditorListener listener) {
		if (cellEditorListeners.contains(listener)) {
			throw new IllegalArgumentException("Listener has already been added: " + listener);
		}
		cellEditorListeners.add(listener);
	}

	/**
	 * Removes the given listener from this class if it has previously been added.
	 * @param listener The listener to remove.
	 */
	public void removeCellEditorListener(CellEditorListener listener) {
		cellEditorListeners.remove(listener);
	}

	private void fireUserChoiceMade(T selectedItem) {
		for (DropDownSelectionChoiceListener<T> listener : choiceListeners) {
			listener.selectionChanged(selectedItem);
		}
	}

	private void fireEditingCancelled() {
		updateManager.stop();
		hideMatchingWindow();
		storeSelectedValue(null);
		ChangeEvent event = new ChangeEvent(this);
		for (CellEditorListener listener : cellEditorListeners) {
			listener.editingCanceled(event);
		}
	}

	private void fireEditingStopped() {
		updateManager.stop();
		hideMatchingWindow();
		ChangeEvent event = new ChangeEvent(this);
		for (CellEditorListener listener : cellEditorListeners) {
			listener.editingStopped(event);
		}
	}

	private void createMatchingWindow() {
		Window parentWindow = WindowUtilities.windowForComponent(this);

		if (parentWindow == null) {
			// maybe we are in a transition phase?
			return;
		}

		// We need to know when to change the size and location of our window.  We call remove
		// first, in case we've already added the listener before
		parentWindow.removeComponentListener(parentWindowListener);
		parentWindow.addComponentListener(parentWindowListener);

		matchingWindow = new JWindow(parentWindow);
		matchingWindow.setFocusable(false);
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED,
			new GColor("color.border.bevel.highlight"), new GColor("color.border.bevel.shadow")));
		scrollPane.setFocusable(false);
		scrollPane.getVerticalScrollBar().setFocusable(false);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.getViewport().add(list);

		matchingWindow.getContentPane().add(scrollPane);
		matchingWindow.setSize(MIN_WIDTH, matchingWindowHeight);

		addUpdateListeners();

		createToolTipWindow(parentWindow);
	}

	private JWindow getMatchingWindow() {
		// make sure our window has been created
		if (matchingWindow == null) {
			createMatchingWindow();
			return matchingWindow;
		}

		// We have a cached window, make sure it is still the current parent window (the window
		// may change when using modal dialogs while reusing this textfield).
		Window currentParentWindow = WindowUtilities.windowForComponent(this);
		if (currentParentWindow != matchingWindow.getParent()) {
			createMatchingWindow();
		}

		return matchingWindow;
	}

	private void createToolTipWindow(Window parent) {
		toolTipWindow = new JWindow(parent);
		toolTipWindow.setFocusable(false);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBorder(new BevelBorder(BevelBorder.RAISED));
		scrollPane.setFocusable(false);
		scrollPane.getVerticalScrollBar().setFocusable(false);
		scrollPane.getHorizontalScrollBar().setFocusable(false);
		scrollPane.getViewport().add(getPreviewPaneComponent());

		toolTipWindow.getContentPane().add(scrollPane);
	}

	private void storeSelectedValue(T newValue) {
		selectedValue = newValue;
	}

	@SuppressWarnings("unchecked")
	// we know the cast is safe because we put the items in the list
	protected void setTextFromList() {
		Object selectedItem = list.getSelectedValue();
		if (selectedItem != null) {
			storeSelectedValue((T) selectedItem);
			setText(dataModel.getDisplayText(selectedValue));
			hideMatchingWindow();
			fireUserChoiceMade((T) selectedItem);
		}
	}

	private void setTextFromDoubleClick(MouseEvent event) {
		int row = list.locationToIndex(event.getPoint());
		T clickedItem = list.getModel().getElementAt(row);
		storeSelectedValue(clickedItem);
		setText(dataModel.getDisplayText(selectedValue));
		hideMatchingWindow();
		fireUserChoiceMade(clickedItem);
	}

	/**
	 * This is more complicated that responding to the user mouse click.  When clicked, the user is
	 * signalling to use the clicked item.  When pressing Enter, they may have been typing and
	 * ignoring the list, so we have to do some validation.
	 */
	@SuppressWarnings("unchecked") // the item better be our type
	private void setTextFromListOnEnterPress() {
		Object selectedItem = list.getSelectedValue();
		if (selectedItem == null) {
			return;
		}

		String textFieldText = getText();
		if (!shouldReplaceTextFieldTextWithSelectedItem(textFieldText, (T) selectedItem)) {
			// The selected item text does not start with the text in the text field, which
			// implies the user has added or changed text and the list has not yet been updated.
			return;
		}

		setTextFromList();
	}

	protected boolean shouldReplaceTextFieldTextWithSelectedItem(String textFieldText,
			T selectedItem) {
		String listItemText = dataModel.getDisplayText(selectedItem);
		return StringUtilities.startsWithIgnoreCase(listItemText, textFieldText);
	}

	/**
	 * Returns the user's selection or null if the user has not made a selection.
	 * <p>
	 * Note: the value returned from this method may not match the text in the field in the
	 * case that the user has selected a value and then typed some text.
	 *
	 * @return the user's selection or null if the user has not made a selection.
	 */
	public T getSelectedValue() {
		return selectedValue;
	}

	/**
	 * Sets the current selection on this text field.  This will store the provided value and set
	 * the text of the text field to be the name of that value.  If the given value is null, then
	 * the text of this field will be cleared.
	 *
	 * @param value The value that is to be the current selection or null to clear the selected
	 * value of this text field.
	 */
	public void setSelectedValue(T value) {
		storeSelectedValue(value);
		if (value != null) {
			setText(dataModel.getDisplayText(value));
			setToolTipText(dataModel.getDescription(value));
		}
		else {
			setText("");
			setToolTipText("");
		}
	}

	/**
	 * Closes the drop down window
	 */
	public void closeDropDownWindow() {
		hideMatchingWindow();
	}

	private void showMatchingWindow() {
		JWindow w = getMatchingWindow();
		w.setVisible(true);
		windowVisibilityListener.windowShown(this);
	}

	protected void hideMatchingWindow() {
		if (matchingWindow != null && matchingWindow.isShowing()) {
			matchingWindow.setVisible(false);
			windowVisibilityListener.windowHidden(this);
			toolTipWindow.setVisible(false);
			list.clearSelection();
		}
	}

	/*testing*/ JList<T> getJList() {
		return list;
	}

	/*testing*/ JWindow getActiveMatchingWindow() {
		return matchingWindow;
	}

	/*testing*/ void setMatchingWindowVisibilityListener(DropDownWindowVisibilityListener<T> l) {
		windowVisibilityListener = Objects.requireNonNull(l);
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);

		if (searchMode == SearchMode.UNKNOWN) {
			return;
		}

		String modeHint = searchMode.getHint();
		searchModeBounds = calculateSearchModeBounds(modeHint, g);

		Color textColor = searchModeIsHovered ? Colors.FOREGROUND : Messages.HINT;

		Graphics2D g2 = (Graphics2D) g;
		g2.setColor(textColor);
		g2.setFont(g2.getFont().deriveFont(Font.ITALIC));
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		Dimension size = getSize();
		Insets insets = getInsets();
		int bottomPad = 3;
		int x = searchModeBounds.getTextStartX();
		int y = size.height - (insets.bottom + bottomPad); // strings paint bottom-up

		g2.drawString(modeHint, x, y);

		// debug
		// g.setColor(Color.ORANGE);
		// g2.draw(searchModeBounds.hoverAreaBounds);
	}

	private SearchModeBounds calculateSearchModeBounds(String text, Graphics g) {
		if (searchModeBounds != null) {
			return searchModeBounds;
		}

		Graphics2D g2d = (Graphics2D) g;
		Font f = g.getFont();
		FontRenderContext frc = g2d.getFontRenderContext();
		char[] chars = text.toCharArray();
		int n = text.length();
		GlyphVector gv = f.layoutGlyphVector(frc, chars, 0, n, Font.LAYOUT_LEFT_TO_RIGHT);
		Rectangle2D bounds2d = gv.getVisualBounds();

		searchModeBounds = new SearchModeBounds(bounds2d.getBounds());
		return searchModeBounds;
	}

	/**
	 * Returns the search mode bounds.  This is the area of the text field that shows the current 
	 * search mode.   This area can be hovered and clicked by the user.  If there are not multiple
	 * search modes available, then this area is not painted and the bounds will be null.  This 
	 * value will get updated as this text field is resized.
	 * 
	 * @return the search mode bounds
	 */
	public SearchModeBounds getSearchModeBounds() {
		return searchModeBounds;
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	protected class DropDownList extends GList<T> {
		@Override
		public void setFont(Font f) {
			super.setFont(f);
			updateCellDimensions(f);
		}

		private void updateCellDimensions(Font font) {

			if (font == null || list == null) {
				return; // UI is initializing
			}

			FontMetrics fontMetrics = list.getFontMetrics(font);
			int padding = 2; // top and bottom border height
			int lineHeight = fontMetrics.getHeight() + padding;
			int iconAndPaddingHeight = 16 + padding;
			int cellHeight = Math.max(lineHeight, iconAndPaddingHeight);

			list.setFixedCellHeight(cellHeight);
			list.setFixedCellWidth(MIN_WIDTH - 20); // add some fudge for scrollbars
		}
	}

	private class HideWindowFocusListener extends FocusAdapter {
		@Override
		public void focusLost(FocusEvent event) {
			Component newFocusOwner = event.getOppositeComponent();
			if (CollectionUtils.isOneOf(newFocusOwner, list, matchingWindow, toolTipWindow)) {
				return;
			}

			textFieldNotFocused = true;
			hideMatchingWindow();
		}

		@Override
		public void focusGained(FocusEvent e) {
			textFieldNotFocused = false;
		}
	}

	private class ListSelectionMouseListener extends MouseAdapter {
		@Override
		public void mouseClicked(MouseEvent event) {
			if (event.getClickCount() == 1) {
				setTextFromSelectedListItemAndKeepMatchingWindowOpen();
			}
			else if (event.getClickCount() > 1) {

				if (selctionIsAllowed()) {
					setTextFromList();
				}
				else {
					// When no selection is allowed, it is still nice to let the user trigger
					// selections via double-click.  If we find cases where this does not make
					// sense, then we can make this an optional operation.
					setTextFromDoubleClick(event);
				}
			}
		}

		private boolean selctionIsAllowed() {
			ListSelectionModel model = list.getSelectionModel();
			return !(model instanceof DropDownTextField.NoSelectionAllowedListSelectionModel);
		}
	}

	private class UpdateCaretListener implements CaretListener {
		@Override
		public void caretUpdate(CaretEvent event) {
			maybeUpdateDisplayContents(false);
		}
	}

	private class UpdateDocumentListener implements DocumentListener {
		@Override
		public void changedUpdate(DocumentEvent event) {
			updateDisplayContents(getText());
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			updateDisplayContents(getText());
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			updateDisplayContents(getText());
		}
	}

	private class WindowComponentListener extends ComponentAdapter {
		@Override
		public void componentHidden(ComponentEvent event) {
			hideMatchingWindow();
		}

		@Override
		public void componentMoved(ComponentEvent event) {
			JWindow window = getMatchingWindow();
			if (window == null) {
				return; // transition state
			}
			updateDisplayLocation(window.isShowing());
		}

		@Override
		public void componentResized(ComponentEvent event) {
			JWindow window = getMatchingWindow();
			if (window == null) {
				return; // transition state
			}
			updateDisplayLocation(window.isShowing());
		}
	}

	private class InternalKeyListener extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent event) {
			// make sure that the matching window has been created; this is the only way to
			// reliably create the window once we've been shown
			getMatchingWindow();

			//@formatter:off
			int keyCode = event.getKeyCode();
			if (CollectionUtils.isOneOf(keyCode, KeyEvent.VK_UP,
												 KeyEvent.VK_DOWN,
												 KeyEvent.VK_KP_UP,
												 KeyEvent.VK_KP_DOWN)) {
			//@formatter:on

				handleArrowKey(event);
			}
			else if (keyCode == KeyEvent.VK_ENTER) {
				handleEnterKey(event);
			}
			else if (keyCode == KeyEvent.VK_ESCAPE) {
				handleEscapeKey(event);
			}

			setToolTipText(getToolTipText());
		}

		private void handleEscapeKey(KeyEvent event) {
			if (getMatchingWindow().isShowing()) {
				hideMatchingWindow();
			}
			else {
				fireEditingCancelled();
			}
			event.consume();
		}

		private void handleEnterKey(KeyEvent event) {

			if (ignoreEnterKeyPress) {
				return;
			}

			// O.K., if we are consuming key presses, then we only want to do so when the selection
			// window is showing.  This will close the selection window and not send the Enter event up
			// to our parent component.
			boolean listShowing = isMatchingListShowing();
			if (consumeEnterKeyPress) {
				if (listShowing) {
					setTextFromListOnEnterPress();
					validateChosenItemAgainstText(true);
					event.consume();
					return; // don't let our parent see the event
				}

				validateChosenItemAgainstText(false);
				fireEditingStopped();

				// Even though 'consumeEnterKeyPress' is set, do not consume the event so that our
				// parent can process the event.
				return;
			}

			// When we aren't consuming Enter key presses, then just take the user's selection and 
			// signal that editing is finished, while letting our parent component handle the event
			setTextFromListOnEnterPress();
			validateChosenItemAgainstText(listShowing);
			fireEditingStopped();
		}
	}

	private void handleArrowKey(KeyEvent event) {

		if (getMatchingWindow().isShowing()) {
			handleArrowKeyForMatchingWindow(event);
			return;
		}

		// Contrl-Up/Down is for toggling the search mode
		if (event.isControlDown()) {
			int keyCode = event.getKeyCode();
			boolean forward = keyCode == KeyEvent.VK_DOWN || keyCode == KeyEvent.VK_KP_DOWN;
			toggleSearchMode(forward);
			return;
		}

		updateDisplayContents(getText());
		event.consume();
	}

	private void handleArrowKeyForMatchingWindow(KeyEvent event) {
		int keyCode = event.getKeyCode();
		if (keyCode == KeyEvent.VK_UP || keyCode == KeyEvent.VK_KP_UP) {
			decrementListSelection();
		}
		else {
			incrementListSelection();
		}
		event.consume();
		setTextFromSelectedListItemAndKeepMatchingWindowOpen();
	}

	private void incrementListSelection() {
		int index = list.getSelectedIndex();
		int listSize = list.getModel().getSize();

		if (index < 0) { // no selection
			index = 0;
		}
		else if (index == listSize - 1) { // last element selected - wrap
			index = 0;
		}
		else { // just increment
			index++;
		}

		list.setSelectedIndex(index);
		list.ensureIndexIsVisible(index);
	}

	private void decrementListSelection() {
		int index = list.getSelectedIndex();
		int listSize = list.getModel().getSize();

		if (index < 0) { // no selection
			index = 0;
		}
		else if (index == 0) { // first element - wrap
			index = listSize - 1;
		}
		else { // just decrement
			index--;
		}

		list.setSelectedIndex(index);
		list.ensureIndexIsVisible(index);
	}

	// we know the cast is safe because we put the items in the list
	protected void setTextFromSelectedListItemAndKeepMatchingWindowOpen() {
		T selectedItem = list.getSelectedValue();
		if (selectedItem == null) {
			return;
		}

		internallyDrivenUpdate = true;
		storeSelectedValue(selectedItem);
		setTextWithoutClosingCompletionWindow(dataModel.getDisplayText(selectedValue));
		fireUserChoiceMade(selectedItem);
	}

	private class PreviewListener implements ListSelectionListener {
		@Override
		public void valueChanged(ListSelectionEvent e) {
			if (e.getValueIsAdjusting()) {
				return;
			}

			T value = list.getSelectedValue();
			String text = "";
			if (value != null) {
				text = dataModel.getDescription(value);
			}
			previewLabel.setText(text);
		}
	}

	private class NoSelectionAllowedListSelectionModel extends DefaultListSelectionModel {

		@Override
		public void setSelectionMode(int selectionMode) {
			// stub
		}

		@Override
		public void addListSelectionListener(ListSelectionListener l) {
			// stub
		}

		@Override
		public void removeListSelectionListener(ListSelectionListener l) {
			// stub
		}

		@Override
		public void setLeadAnchorNotificationEnabled(boolean flag) {
			// stub
		}

		@Override
		public void setSelectionInterval(int index0, int index1) {
			// stub
		}

		@Override
		public void addSelectionInterval(int index0, int index1) {
			// stub
		}

		@Override
		public void setValueIsAdjusting(boolean isAdjusting) {
			// stub
		}

		@Override
		public void setAnchorSelectionIndex(int anchorIndex) {
			// stub
		}

		@Override
		public void setLeadSelectionIndex(int leadIndex) {
			// stub
		}
	}

	private class SearchModeMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.getClickCount() != 1) {
				return;
			}

			if (!isOverSearchMode(e)) {
				return;
			}

			boolean forward = !e.isControlDown();
			toggleSearchMode(forward);
		}

		private void updateSearchModeHover(MouseEvent e) {
			searchModeIsHovered = isOverSearchMode(e);
			String tip =
				searchModeIsHovered ? "Search Mode: " + searchMode.getDisplayName() : null;
			setToolTipText(tip);
			setCursor(searchModeIsHovered ? CURSOR_HAND : CURSOR_DEFAULT);
			repaint();
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			updateSearchModeHover(e);
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			updateSearchModeHover(e);
		}

		@Override
		public void mouseExited(MouseEvent e) {
			updateSearchModeHover(e);
		}
	}

	private class SearchModeHelpLocation implements DynamicHelpLocation {

		// Note the help for this generic field currently lives in the help for the Data Type 
		// chooser, which is a bit odd, but convenient.  To fix this, we would need a separate help
		// page for the generic text field.
		private HelpLocation helpLocation = new HelpLocation("DataTypeEditors", "SearchMode");

		@Override
		public HelpLocation getActiveHelpLocation() {
			if (searchModeIsHovered) {
				return helpLocation;
			}
			return null;
		}
	}

	/**
	 * Represents the bounds of the search mode area in this text field.  This also tracks the text
	 * position within the search mode bounds.
	 */
	public class SearchModeBounds {
		private Rectangle textBounds;
		private Rectangle hoverAreaBounds;

		SearchModeBounds(Rectangle textBounds) {
			this.textBounds = textBounds;

			Dimension size = getSize();
			Insets insets = getInsets();
			hoverAreaBounds = new Rectangle(textBounds);
			hoverAreaBounds.width += 10; // add some padding

			// same height as this field
			hoverAreaBounds.height = getHeight() - (insets.top + insets.bottom);

			// move away from the end of this field
			hoverAreaBounds.x = size.width - insets.right - hoverAreaBounds.width;
			hoverAreaBounds.y = insets.top;
		}

		public Rectangle getHoverAreaBounds() {
			return hoverAreaBounds;
		}

		boolean isHovered(Point p) {
			return hoverAreaBounds.contains(p);
		}

		Point getLocation() {
			return hoverAreaBounds.getLocation();
		}

		int getTextWidth() {
			return textBounds.width;
		}

		int getTextStartX() {
			return (int) hoverAreaBounds.getCenterX() - (getTextWidth() / 2);
		}
	}

}
