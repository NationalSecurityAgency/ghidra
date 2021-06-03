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
package docking.widgets.autocomplete;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.Caret;

import docking.DockingUtils;
import docking.DockingUtils.TreeTraversalResult;
import docking.widgets.textfield.TextFieldLinker;
import generic.util.WindowUtilities;
import ghidra.util.task.SwingUpdateManager;

/**
 * An autocompleter that may be attached to one or more {@link JTextField}.
 * 
 * Each autocompleter instance has one associated window (displaying the list of suggestions) and
 * one associated model (generating the list of suggestions). Thus, the list can only be active on
 * one of the attached text fields at a time. This is usually the desired behavior, and it allows
 * for one autocompleter to be reused on many fields. Behavior is undefined when multiple
 * autocompleters are attached to the same text field. More likely, you should implement a
 * composite model if you wish to present completions from multiple models on a single text field.
 * 
 * By default, the autocompleter is activated when the user presses CTRL-SPACE, at which point, the
 * model is queried for possible suggestions. The completer gives the model all the text preceding
 * the current field's caret. This behavior can be changed by overriding the
 * {@link #getPrefix(JTextField)} method. This may be useful, e.g., to obtain a prefix for
 * the current word, rather than the full field contents, preceding the caret. The list is
 * displayed such that its top-left corner is placed directly under the current field's caret. As
 * the user continues typing, the suggestions are re-computed, and the list tracks with the caret.
 * This positioning behavior can be modified by overriding the
 * {@link #getCompletionWindowPosition()} method. As a convenience, the
 * {@link #getCaretPositionOnScreen(JTextField)} method is available to compute the default
 * position.
 * 
 * Whether or not the list is currently displayed, when the user presses CTRL-SPACE, if only one
 * completion is possible, it is automatically activated. This logic is applied again and again,
 * until either no suggestions are given, or more than one suggestion is given (or until the
 * autocompleter detects an infinite loop). This behavior can by modified on an item-by-item basis
 * by overriding the {@link #getCompletionCanDefault(Object) getCompletionCanDefault(T)} method. This same behavior can be
 * activated by calling the {@link #startCompletion(JTextField)} method, which may be useful, e.g.,
 * to bind a different key sequence to start autocompletion.
 * 
 * The appearance of each item in the suggestion list can be modified by overriding the various
 * {@code getCompletion...} methods. Note that it's possible for an item to be displayed one way,
 * but cause the insertion of different text. In any case, it is best to ensure any modification
 * produces an intuitive behavior.
 * 
 * The simplest use case is to create a text field, create an autocompleter with a custom model,
 * and then attach and show.
 * 
 *
 * <pre>
 * JTextField field = new JTextField();
 * 
 * {@code AutocompletionModel<String> model = new AutocompletionModel<String>() }{
 *     &#64;Override
 *     {@code public Collection<String> computeCompletions(String text)} {
 *         ... // Populate the completion list based on the given prefix.
 *     }
 * }
 * {@code TextFieldAutocompleter<String> completer = new TextFieldAutocompleter<String>(model);
 * completer.attachTo(field);
 * ... // Add the field to, e.g., a dialog, and show.
 * }</pre>
 * 
 * @param <T> the type of suggestions presented by this autocompleter.
 */
public class TextFieldAutocompleter<T> {
	private static final int DEFAULT_UPDATE_DELAY = 10;
	private static final int DEFAULT_MAX_UPDATE_DELAY = 2000;
	// TODO: Maybe compute the default dimensions based on content?
	private static final int MIN_HEIGHT = 100;
	private static final int MIN_WIDTH = 200;
	private static final int DEFAULT_HEIGHT = MIN_HEIGHT * 3;
	private static final int DEFAULT_WIDTH = MIN_WIDTH;

	// Variables to keep track of state
	private final AutocompletionModel<T> model;
	private final Set<JTextField> attachees = new HashSet<>();
	private JTextField focus;
	private List<AutocompletionListener<T>> autocompletionListeners = new ArrayList<>();

	// Swing fodder
	// window has delayed initialization for parenting
	private JWindow completionWindow;
	private JPanel content = new JPanel(new BorderLayout());
	private JScrollPane scrollPane = new JScrollPane();
	private DefaultListModel<T> listModel = new DefaultListModel<>();
	private DefaultListModel<T> blankModel = new DefaultListModel<>();
	private JList<T> list = new JList<>(listModel);
	private MyListener listener = new MyListener();

	private boolean pendingTextUpdate;
	private SwingUpdateManager updateManager = new SwingUpdateManager(DEFAULT_UPDATE_DELAY,
		DEFAULT_MAX_UPDATE_DELAY, "Auto Completion Update Manager " + this.getClass(), () -> {
			if (pendingTextUpdate == false) {
				return; // not sure if this can happen
			}
			doUpdateDisplayContents();
			pendingTextUpdate = false;
		});

	// Prepare all the swing components (except the window)
	{
		content.setBorder(
			BorderFactory.createBevelBorder(BevelBorder.RAISED, Color.LIGHT_GRAY, Color.GRAY));
		scrollPane.setBorder(
			BorderFactory.createBevelBorder(BevelBorder.LOWERED, Color.LIGHT_GRAY, Color.GRAY));
		//content.setFocusable(false);

		scrollPane.getVerticalScrollBar().setFocusable(false);
		//scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.getViewport().add(list);

		MouseAdapter resizeListener = new ResizeListener();
		scrollPane.addMouseMotionListener(resizeListener);
		scrollPane.addMouseListener(resizeListener);
		content.addMouseMotionListener(resizeListener);
		content.addMouseListener(resizeListener);

		addContent(content);

		list.setCellRenderer(buildListCellRenderer());
		list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		list.addMouseListener(listener);

		content.add(scrollPane);

		DockingUtils.forAllDescendants(content, (c) -> {
			c.setFocusable(false);
			return TreeTraversalResult.CONTINUE;
		});
	}

	public void dispose() {
		updateManager.dispose();
	}

	protected void addContent(JPanel contentPanel) {
		// Extension point
	}

	/**
	 * A mouse listener that resizes the auto-completion list window
	 */
	class ResizeListener extends MouseAdapter {
		protected static final int REGION_NONE = 0;
		protected static final int REGION_E = 1;
		protected static final int REGION_S = 2;
		protected static final int REGION_SE = 3;

		protected int grabbedRegion = REGION_NONE;
		protected int xoff = 0;
		protected int yoff = 0;

		@Override
		public void mousePressed(MouseEvent e) {
			grabbedRegion = getRegion(e);
			xoff = completionWindow.getWidth() - e.getX();
			yoff = completionWindow.getHeight() - e.getY();
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			grabbedRegion = REGION_NONE;
		}

		protected int getRegion(MouseEvent e) {
			Insets insets = content.getInsets();
			JScrollBar hbar = scrollPane.getHorizontalScrollBar();
			JScrollBar vbar = scrollPane.getVerticalScrollBar();
			int vdim = 0;
			if (hbar != null && hbar.isVisible()) {
				vdim = hbar.getHeight();
			}
			int hdim = 0;
			if (vbar != null && vbar.isVisible()) {
				hdim = vbar.getWidth();
			}
			boolean nearRight = e.getX() >= content.getWidth() - insets.right - hdim;
			boolean nearBottom = e.getY() >= content.getHeight() - insets.bottom - vdim;
			boolean closeRight = e.getX() >= content.getWidth() - 20;
			boolean closeBottom = e.getY() >= content.getHeight() - 20;
			if (nearRight && nearBottom || nearRight && closeBottom || closeRight && nearBottom) {
				return REGION_SE;
			}
			else if (nearRight) {
				return REGION_E;
			}
			else if (nearBottom) {
				return REGION_S;
			}
			return REGION_NONE;
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			switch (getRegion(e)) {
				case REGION_E:
					content.setCursor(Cursor.getPredefinedCursor(Cursor.E_RESIZE_CURSOR));
					break;
				case REGION_S:
					content.setCursor(Cursor.getPredefinedCursor(Cursor.S_RESIZE_CURSOR));
					break;
				case REGION_SE:
					content.setCursor(Cursor.getPredefinedCursor(Cursor.SE_RESIZE_CURSOR));
					break;
				default:
					content.setCursor(null);
			}
		}

		@Override
		public void mouseExited(MouseEvent e) {
			content.setCursor(null);
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			// Blank
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			if (grabbedRegion == 0) {
				return;
			}
			Dimension size = completionWindow.getSize();
			if ((grabbedRegion & REGION_E) != 0) {
				size.width = Math.max(MIN_WIDTH, e.getXOnScreen() - completionWindow.getX() + xoff);
			}
			if ((grabbedRegion & REGION_S) != 0) {
				size.height =
					Math.max(MIN_HEIGHT, e.getYOnScreen() - completionWindow.getY() + yoff);
			}
			completionWindow.setSize(size);
		}
	}

	/**
	 * Create a new autocompleter associated with the given model.
	 * @param model the model giving the suggestions.
	 */
	public TextFieldAutocompleter(AutocompletionModel<T> model) {
		this.model = model;
	}

	/**
	 * Recompute the display location and move with list window.
	 * 
	 * This is useful, e.g., when the window containing the associated text field(s) moves.
	 */
	public void updateDisplayLocation() {
		SwingUtilities.invokeLater(() -> {
			doUpdateDisplayLocation();
		});
	}

	/**
	 * Update the contents of the suggestion list.
	 * 
	 * This entails taking the prefix, querying the model, and rendering the list.
	 */
	protected void updateDisplayContents() {
		pendingTextUpdate = true;
		updateManager.updateLater();
	}

	/*
	 * The actual implementation of updateDisplayContents, which gets scheduled asynchronously.
	 */
	private void doUpdateDisplayContents() {
		if (focus == null) {
			return;
		}
		if (completionWindow == null || !completionWindow.isVisible()) {
			return;
		}
		String text = getPrefix(focus);
		final Collection<T> completions = model.computeCompletions(text);
		if (completions == null || completions.size() == 0) {
			setCompletionListVisible(false);
			return;
		}
		doUpdateDisplayLocation();
		list.setModel(blankModel);
		listModel.clear();
		for (T t : completions) {
			listModel.addElement(t);
		}
		list.setModel(listModel);
		select(0);
	}

	/**
	 * Dispose of the completion window resources.
	 */
	protected void destroyCompletionWindow() {
		completionWindow.remove(content);
		completionWindow.dispose();
		completionWindow = null;
	}

	/**
	 * Build the completion window, parented to the attached field that last had focus.
	 */
	protected void buildCompletionWindow() {
		completionWindow = new JWindow(WindowUtilities.windowForComponent(focus));
		completionWindow.add(content);
		content.setVisible(true);
		list.setVisible(true);
		Dimension size = getDefaultCompletionWindowDimension();
		if (-1 == size.height) {
			size.height = DEFAULT_HEIGHT;
		}
		if (-1 == size.width) {
			size.width = DEFAULT_WIDTH;
		}
		completionWindow.setSize(size);
	}

	/**
	 * Show or hide the completion list window
	 * @param visible true to show, false to hide
	 */
	public void setCompletionListVisible(boolean visible) {
		if (visible) {
			if (completionWindow == null) {
				buildCompletionWindow();
			}
			else if (completionWindow.getOwner() != WindowUtilities.windowForComponent(focus)) {
				destroyCompletionWindow();
				buildCompletionWindow();
			}
			completionWindow.setVisible(true);
		}
		else if (completionWindow != null) {
			completionWindow.setVisible(false);
		}
	}

	/**
	 * Check if the completion list window is visible.
	 * 
	 * If it is visible, this implies that the user is actively using the autocompleter.
	 * @return true if shown, false if hidden.
	 */
	public boolean isCompletionListVisible() {
		return completionWindow != null && completionWindow.isVisible();
	}

	/*
	 * The actual implementation of updateDisplayLocation, which is scheduled asynchronously.
	 */
	private void doUpdateDisplayLocation() {
		Point p = getCompletionWindowPosition();
		completionWindow.setLocation(p);
	}

	/**
	 * Gets the prefix from the given text field, used to query the model.
	 * 
	 * @param field an attached field, usually the one with focus.
	 * @return the prefix to use as the query.
	 */
	protected String getPrefix(JTextField field) {
		try {
			return field.getText(0, field.getCaretPosition());
		}
		catch (BadLocationException e) {
			throw new AssertionError("INTERNAL: Should not be here", e);
		}
	}

	/**
	 * Get the preferred location (on screen) of the completion list window.
	 * 
	 * Typically, this is a location near the focused field. Ideally, it is positioned such that
	 * the displayed suggestions coincide with the applicable text in the focused field. For
	 * example, if the suggestions display some portion of the prefix, the window could be
	 * positioned such that the portion in the suggestion appears directly below the same portion
	 * in the field.
	 * @return the point giving the top-left corner of the completion window
	 */
	protected Point getCompletionWindowPosition() {
		return getCaretPositionOnScreen(focus);
	}

	/**
	 * Get the preferred dimensions of the completion list window.
	 * 
	 * Typically, this is the width of the focused field.
	 * @return the dimension giving the preferred height and width. A value can be -1 to indicate
	 *         no preference.
	 */
	protected Dimension getDefaultCompletionWindowDimension() {
		return new Dimension(focus.getWidth(), -1);
	}

	/**
	 * A convenience function that returns the bottom on-screen position of the given field's
	 * caret.
	 * 
	 * @param field the field, typically the one having focus
	 * @return the on-screen position of the caret's bottom.
	 */
	protected Point getCaretPositionOnScreen(JTextField field) {
		FontMetrics metrics = field.getFontMetrics(field.getFont());
		Caret c = field.getCaret();
		Point p = c.getMagicCaretPosition(); // returns a shared reference
		if (p == null) {
			p = new Point(0, field.getBaseline(1, 1));
		}
		else {
			p = new Point(p);
		}
		p.y += metrics.getHeight();
		SwingUtilities.convertPointToScreen(p, field);
		return p;
	}

	/**
	 * Builds the list cell renderer for the autocompletion list.
	 * 
	 * A programmer may override this if the various {@code getCompletion...} methods prove
	 * insufficient for customizing the display of the suggestions. Please remember that
	 * {@link JLabel}s can render HTML, so {@link #getCompletionDisplay(Object) getCompletionDisplay(T)} is quite powerful
	 * with the default {@link AutocompletionCellRenderer}.
	 * @return a list cell renderer for the completion list.
	 */
	protected ListCellRenderer<? super T> buildListCellRenderer() {
		return new AutocompletionCellRenderer<>(this);
	}

	/**
	 * Attach the autocompleter to the given text field.
	 * 
	 * If this method is never called, then the autocompleter can never appear.
	 * @param field the field that will gain this autocompletion feature
	 * @return true, if this field is not already attached
	 */
	public boolean attachTo(JTextField field) {
		if (!attachees.add(field)) {
			return false;
		}
		boolean keep = false;
		try {
			field.addFocusListener(listener);
			field.addCaretListener(listener);
			field.addKeyListener(listener);
			field.getDocument().addDocumentListener(listener);
			keep = true;
		}
		finally {
			if (!keep) {
				attachees.remove(field);
			}
		}
		return keep;
	}

	/**
	 * Deprive the given field of this autocompleter.
	 * 
	 * @param field the field that will lose this autocompletion feature
	 * @return true, if this field was actually attached
	 */
	public boolean detachFrom(JTextField field) {
		if (!attachees.remove(field)) {
			return false;
		}
		field.removeFocusListener(listener);
		field.removeCaretListener(listener);
		field.removeKeyListener(listener);
		field.getDocument().removeDocumentListener(listener);

		return true;
	}

	/**
	 * Cause the currently-selected suggestion to be activated.
	 * 
	 * By default, this is called when the user presses ENTER or clicks a suggestion.
	 */
	protected void activateCurrentCompletion() {
		T sel = list.getSelectedValue();
		if (sel == null) {
			return;
		}
		setCompletionListVisible(false);
		completionActivated(sel);
	}

	/**
	 * Fire the registered autocompletion listeners on the given event.
	 * 
	 * Each registered listener is invoked in order of registration. If any listener consumes the
	 * event, then later-registered listeners will not be notified of the event. If any listener
	 * cancels the event, then the suggested text will not be inserted.
	 * 
	 * @param ev the event
	 * @return true, if no listener cancelled the event
	 */
	protected boolean fireAutocompletionListeners(AutocompletionEvent<T> ev) {
		for (AutocompletionListener<T> l : autocompletionListeners) {
			if (ev.isConsumed()) {
				break;
			}
			l.completionActivated(ev);
		}
		return !ev.isCancelled();
	}

	private void completionActivated(T sel) {
		AutocompletionEvent<T> ev = new AutocompletionEvent<>(sel, focus);
		if (!fireAutocompletionListeners(ev)) {
			return;
		}
		try {
			focus.getDocument().insertString(focus.getCaretPosition(), getCompletionText(sel),
				null);
		}
		catch (BadLocationException e) {
			throw new AssertionError("INTERNAL: Should not be here", e);
		}
	}

	/**
	 * Register the given auto-completion listener
	 * @param l the listener to register
	 */
	public void addAutocompletionListener(AutocompletionListener<T> l) {
		autocompletionListeners.add(l);
	}

	/**
	 * Unregister the given auto-completion listener
	 * @param l the listener to unregister
	 */
	public void removeAutocompletionListener(AutocompletionListener<T> l) {
		autocompletionListeners.remove(l);
	}

	/**
	 * Get all the registered auto-completion listeners
	 * @return an array of registered listeners
	 */
	@SuppressWarnings("unchecked")
	public AutocompletionListener<T>[] getAutocompletionListeners() {
		return autocompletionListeners.toArray(new AutocompletionListener[0]);
	}

	/**
	 * Get all registered listeners of the given type
	 * 
	 * @param listenerType the type of listeners to get
	 * @return an array of registered listeners 
	 */
	@SuppressWarnings({ "unchecked", "hiding" })
	public <T> T[] getListeners(Class<T> listenerType) {
		if (listenerType == AutocompletionListener.class) {
			return (T[]) getAutocompletionListeners();
		}
		return null;
	}

	/**
	 * Get the text to insert when the given suggestion is activated
	 * 
	 * @param sel the activated suggestion
	 * @return the text to insert
	 */
	protected String getCompletionText(T sel) {
		return sel.toString();
	}

	/**
	 * Get the (possibly HTML) text to display for the given suggestion in the list
	 * 
	 * @param sel the suggestion to display
	 * @return the text or HTML representing the suggestion
	 */
	protected String getCompletionDisplay(T sel) {
		return sel.toString();
	}

	/**
	 * Get the foreground color to display for the given suggestion in the list
	 * 
	 * @param sel the suggestion to display
	 * @param isSelected true if the suggestion is currently selected
	 * @param cellHasFocus true if the suggestion currently has focus
	 * @return the foreground color for the suggestion
	 */
	protected Color getCompletionForeground(T sel, boolean isSelected, boolean cellHasFocus) {
		return null;
	}

	/**
	 * Get the background color to display for the given suggestion in the list
	 * 
	 * @param sel the suggestion to display
	 * @param isSelected true if the suggestion is currently selected
	 * @param cellHasFocus true if the suggestion currently has focus
	 * @return the background color for the suggestion
	 */
	protected Color getCompletionBackground(T sel, boolean isSelected, boolean cellHasFocus) {
		return null;
	}

	/**
	 * Get the icon to display with the given suggestion in the list
	 * 
	 * @param sel the suggestion to display
	 * @param isSelected true if the suggestion is currently selected
	 * @param cellHasFocus true if the suggestion currently has focus
	 * @return the icon to display with the suggestion
	 */
	protected Icon getCompletionIcon(T sel, boolean isSelected, boolean cellHasFocus) {
		return null;
	}

	/**
	 * Get the font for the given suggestion in the list
	 * 
	 * @param sel the suggestion to display
	 * @param isSelected true if the suggestion is currently selected
	 * @param cellHasFocus true if the suggestion currently has focus
	 * @return the font to use
	 */
	protected Font getCompletionFont(T sel, boolean isSelected, boolean cellHasFocus) {
		if (focus == null) {
			return null;
		}
		return focus.getFont();
	}

	/**
	 * Decide whether the given suggestion can be automatically activated.
	 * 
	 * When autocompletion is started (via {@link #startCompletion(JTextField)}) or when the user
	 * presses CTRL-SPACE, if there is only a single suggestion, it is taken automatically, and the
	 * process repeats until there is not a sole suggestion. Before the suggestion is taken,
	 * though, it calls this method. If it returns false, the single suggestion is displayed in a
	 * 1-long list instead. This is useful to prevent consequential actions from being
	 * automatically activated by the autocompleter.
	 * 
	 * @param sel the potentially auto-activated suggestion.
	 * @return true to permit auto-activation, false to prevent it.
	 */
	protected boolean getCompletionCanDefault(T sel) {
		return true;
	}

	/**
	 * Starts the autocompleter on the given text field.
	 * 
	 * First, this repeatedly attempts auto-activation. When there are many suggestions, or when
	 * auto-activation is prevented (see {@link #getCompletionCanDefault(Object) getCompletionCanDefault(T)}), a list is displayed
	 * (usually below the caret) containing the suggestions given the fields current contents. The
	 * list remains open until either the user cancels it (usually via ESC) or the user activates
	 * a suggestion. 
	 * 
	 * NOTE: The text field must already be attached.
	 * @param field the field on which to start autocompletion.
	 */
	public void startCompletion(JTextField field) {
		if (!attachees.contains(field)) {
			throw new IllegalArgumentException("Given field is not attached");
		}
		Set<String> visited = new HashSet<>();
		while (true) {
			String before = getPrefix(field);
			if (!visited.add(before)) {
				return;
			}
			Collection<T> comp = model.computeCompletions(before);
			if (comp == null || comp.size() == 0) {
				return;
			}
			else if (comp.size() == 1) {
				T sel = comp.iterator().next();
				if (getCompletionCanDefault(sel)) {
					completionActivated(comp.iterator().next());
				}
				else {
					setCompletionListVisible(true);
					updateDisplayContents();
					return;
				}
			}
			else if (!isCompletionListVisible()) {
				setCompletionListVisible(true);
				updateDisplayContents();
				return;
			}
		}
	}

	/**
	 * Cause the suggestion at the given index to be selected
	 * @param index the index of the selection
	 */
	protected void select(int index) {
		list.setSelectedIndex(index);
		list.ensureIndexIsVisible(index);
	}

	/**
	 * Cause the next suggestion to be selected, wrapping if applicable
	 */
	protected void selectNext() {
		int index = list.getSelectedIndex();
		int size = listModel.getSize();

		index++;
		if (index >= size) {
			index -= size;
		}
		select(index);
	}

	/**
	 * Cause the previous suggestion to be selected, wrapping if applicable
	 */
	protected void selectPrev() {
		int index = list.getSelectedIndex();
		int size = listModel.getSize();
		if (index >= 0) {
			index--;
		}
		if (index < 0) {
			index += size;
		}
		select(index);
	}

	/**
	 * Advance the selection down a page
	 */
	protected void selectNextPage() {
		int index = list.getSelectedIndex();
		int size = listModel.getSize();

		index += 10;
		if (index >= size) {
			index = size - 1;
		}
		select(index);
	}

	/**
	 * Advance the selection up a page
	 */
	protected void selectPrevPage() {
		int index = list.getSelectedIndex();
		int size = listModel.getSize();

		if (size <= 10) {
			select(0);
			return;
		}
		if (index >= 0) {
			index -= 10;
		}
		if (index < 0) {
			index = 0;
		}
		select(index);
	}

	/**
	 * Select the first suggestion
	 */
	protected void selectFirst() {
		select(0);
	}

	/**
	 * Select the last suggestion
	 */
	protected void selectLast() {
		select(listModel.getSize() - 1);
	}

	/**
	 * A listener to handle all the callbacks
	 */
	protected class MyListener
			implements FocusListener, KeyListener, DocumentListener, MouseListener, CaretListener {

		@Override
		public void keyTyped(KeyEvent e) {
			// Nothing
		}

		@Override
		public void keyPressed(KeyEvent e) {
			if (e.isConsumed()) {
				return;
			}
			if (e.getKeyCode() == KeyEvent.VK_ENTER) {
				if (isCompletionListVisible()) {
					activateCurrentCompletion();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_DOWN) {
				if (isCompletionListVisible()) {
					selectNext();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_UP) {
				if (isCompletionListVisible()) {
					selectPrev();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_PAGE_DOWN) {
				if (isCompletionListVisible()) {
					selectNextPage();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_PAGE_UP) {
				if (isCompletionListVisible()) {
					selectPrevPage();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_END) {
				if (isCompletionListVisible()) {
					selectLast();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_HOME) {
				if (isCompletionListVisible()) {
					selectFirst();
					e.consume();
				}
			}
			else if (e.getKeyCode() == KeyEvent.VK_SPACE &&
				(e.getModifiers() & InputEvent.CTRL_MASK) != 0) {
				startCompletion((JTextField) e.getComponent());
				e.consume();
			}
			else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
				if (isCompletionListVisible()) {
					setCompletionListVisible(false);
					e.consume();
				}
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			// Nothing
		}

		@Override
		public void focusGained(FocusEvent e) {
			focus = (JTextField) e.getComponent();
			updateDisplayContents();
		}

		@Override
		public void focusLost(FocusEvent e) {
			Component opp = e.getOppositeComponent();
			if (attachees.contains(opp)) {
				focus = (JTextField) opp;
			}
			else if (opp == list) {
				// Do nothing
			}
			else {
				setCompletionListVisible(false);
				focus = null;
			}
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			updateDisplayContents();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			updateDisplayContents();
		}

		@Override
		public void changedUpdate(DocumentEvent e) {
			// Nothing
		}

		@Override
		public void caretUpdate(CaretEvent e) {
			updateDisplayContents();
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			if (e.getButton() == MouseEvent.BUTTON1) {
				activateCurrentCompletion();
			}
		}

		@Override
		public void mousePressed(MouseEvent e) {
			// Nothing
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			// Nothing
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			// Nothing
		}

		@Override
		public void mouseExited(MouseEvent e) {
			// Nothing
		}
	}

	/**
	 * A demonstration of the autocompleter on a single text field.
	 * 
	 * The autocompleter offers the tails from a list of strings that start with the text before
	 * the caret.
	 */
	public static class TextFieldAutocompleterDemo {
		public static void main(String[] args) {
			JDialog dialog = new JDialog((Window) null, "Autocompleter Demo");
			JTextField field = new JTextField();

			dialog.add(field);

			TextFieldAutocompleter<String> auto =
				new TextFieldAutocompleter<>(new AutocompletionModel<String>() {
					Set<String> strings = new HashSet<>(Arrays.asList(new String[] { "Test",
						"Testing", "Another", "Yet another", "Yet still more" }));
					{
						for (int i = 0; i < 20; i++) {
							strings.add("Item " + i);
						}
					}

					@Override
					public Collection<String> computeCompletions(String text) {
						Set<String> matching = new TreeSet<>();
						for (String s : strings) {
							if (s.startsWith(text)) {
								matching.add(s.substring(text.length()));
							}
						}
						return matching;
					}
				});

			auto.attachTo(field);

			dialog.setBounds(2560, 500, 400, 200);
			dialog.setModal(true);
			dialog.setVisible(true);
		}
	}

	/**
	 * A demonstration of the autocompleter on two linked text fields.
	 * 
	 * This demo was designed to test whether the autocompleter and the {@link TextFieldLinker}
	 * could be composed correctly.
	 */
	public static class DualTextAutocompleterDemo {
		public static void main(String[] args) {
			JDialog dialog = new JDialog((Window) null, "MultiTextField with Autocompleter Demo");

			Box hbox = Box.createHorizontalBox();
			dialog.add(hbox);

			TextFieldLinker dual = TextFieldLinker.twoSpacedFields();

			hbox.add(dual.getField(0));
			hbox.add(Box.createHorizontalStrut(10));
			hbox.add(dual.getField(1));

			dual.setVisible(true);

			AutocompletionModel<String> model = new AutocompletionModel<String>() {
				Set<String> strings =
					new HashSet<>(Arrays.asList(new String[] { "Test", "Testing", "Another",
						"Yet another", "Yet still more", "Yet still even more", "Yetis, yo" }));

				@Override
				public Collection<String> computeCompletions(String text) {
					Set<String> matching = new TreeSet<>();
					for (String s : strings) {
						if (s.startsWith(text)) {
							matching.add(s.substring(text.length()));
						}
					}
					return matching;
				}
			};
			TextFieldAutocompleter<String> auto = new TextFieldAutocompleter<String>(model) {
				@Override
				protected String getPrefix(JTextField field) {
					return dual.getTextBeforeCursor(field);
				}
			};

			auto.attachTo(dual.getField(0));
			auto.attachTo(dual.getField(1));

			dialog.setBounds(2560, 500, 400, 200);
			dialog.setModal(true);
			dialog.setVisible(true);
		}
	}
}
