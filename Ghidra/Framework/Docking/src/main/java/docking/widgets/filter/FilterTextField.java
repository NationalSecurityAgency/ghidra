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
package docking.widgets.filter;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import utility.function.Callback;

/**
 * A text field that is meant to be used in conjunction with tables that allow filter text.  This
 * text field will change its background color when it contains text.  Additionally, this text
 * field will flash its background color when the associated component gains focus.  This is done
 * to remind the user that there is a filter applied.
 */
public class FilterTextField extends JPanel {

	private static final Integer BASE_COMPONENT_LAYER = 1;
	private static final Integer HOVER_COMPONENT_LAYER = 2;

	private static final long MINIMUM_TIME_BETWEEN_FLASHES_MS = 5000;
	private static final int FLASH_FREQUENCY_MS = 250;

	private static Color FLASH_BACKGROUND_COLOR = Color.WHITE;
	private static Color FILTERED_BACKGROUND_COLOR = Color.YELLOW;
	/*package*/ static Color UNEDITABLE_BACKGROUND_COLOR = Color.LIGHT_GRAY;

	private Color noFlashColor;

	/** Signals the last flash time (used to prevent excessive flashing) */
	private long lastFlashTime = 0;
	private Timer flashTimer = new BackgroundFlashTimer();
	private boolean hasText;

	private JLayeredPane layeredPane;
	private JTextField textField = new JTextField();
	private ClearFilterLabel clearLabel = new ClearFilterLabel(textField);

	private Component focusComponent;
	private FocusListener flashFocusListener = new FlashFocusListener();

	private WeakSet<FilterListener> listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();
	private WeakSet<Callback> enterListeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();

	/**
	 * Constructs this text field with the given component.  <code>component</code> may be null, but 
	 * then this field will be unable to flash in response to focus events (see the header 
	 * documentation).
	 * 
	 * @param component The component needed to listen for focus changes, may be null.
	 */
	public FilterTextField(Component component) {
		this(component, 0);
	}

	/**
	 * Constructs this text field with the given component and the preferred visible column 
	 * width.  <code>component</code> may be null, but then this field will be able to flash in
	 * response to focus events (see the header documentation).
	 * @param component The component needed to listen for focus changes, may be null.
	 * @param columns The number of preferred visible columns (see JTextField)
	 */
	public FilterTextField(Component component, int columns) {
		super(new BorderLayout());

		textField.setColumns(columns);

		setFocusComponent(component);

		textField.addKeyListener(new TraversalKeyListener(component));
		textField.getDocument().addDocumentListener(new FilterDocumentListener());
		textField.addActionListener(e -> notifyEnterPressed());

		layeredPane = new JLayeredPane() {
			@Override
			public Dimension getPreferredSize() {
				Insets insets = getInsets();
				Dimension ps = textField.getPreferredSize();
				ps.width += insets.left + insets.right;
				ps.height += insets.top + insets.bottom;
				return ps;
			}
		};
		layeredPane.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
		layeredPane.add(textField, BASE_COMPONENT_LAYER);
		layeredPane.add(clearLabel, HOVER_COMPONENT_LAYER);
		clearLabel.setVisible(false);

		layeredPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(java.awt.event.ComponentEvent e) {
				Dimension preferredSize = layeredPane.getSize();
				Insets insets = layeredPane.getInsets();
				int x = insets.left;
				int y = insets.top;
				int width = preferredSize.width - insets.right - x;
				int height = preferredSize.height - (insets.top + insets.bottom);
				textField.setBounds(x, y, width, height);
			}
		});

		add(layeredPane, BorderLayout.NORTH);
	}

	private void notifyEnterPressed() {
		enterListeners.forEach(l -> l.call());
	}

	public void setFocusComponent(Component component) {
		if (focusComponent != null) {
			focusComponent.removeFocusListener(flashFocusListener);
		}

		focusComponent = component;

		if (focusComponent != null) {
			focusComponent.addFocusListener(flashFocusListener);
		}
	}

	private void flashFilterBorder() {
		if (!hasText || !isEditable()) {
			return;
		}

		if ((System.currentTimeMillis() - lastFlashTime) < getMinimumTimeBetweenFlashes()) {
			return;
		}

		flashTimer.restart();
	}

	private Color getDefaultBackgroundColor() {
		if (noFlashColor == null) {
			noFlashColor = textField.getBackground();  // lazy init to default bg color
		}
		return noFlashColor;
	}

	/**
	 * This method will signal to the users if a filter is currently applied (has text).  For 
	 * example, the default implementation will 'flash' the filter by changing its background
	 * color multiple times.
	 * <p>
	 * Note: this method will not perform the alert if the minimum time between alerts 
	 * has not passed.  To force the alter to take place, call {@link #alert(boolean)} with a
	 * value of <code>true</code>.
	 */
	public void alert() {
		alert(false);
	}

	/**
	 * This is the same as {@link #alert()} with the exception that a <code>true</code> value for
	 * <code>forceAlter</code> will guarantee that the alert will happen.  A <code>false</code> value
	 * will not perform the alert if the minimum time between alerts has not passed.
	 * @param forceAlert true signals to force the alter to take place.
	 * @see #alert()
	 */
	public void alert(boolean forceAlert) {
		if (forceAlert) {
			resetFocusFlashing();
		}
		flashFilterBorder();
	}

	/** Keeps the focus from flashing for a bit */
	private void stallFocusFlashing() {
		// this prevents focus from flashing for MINIMUM_TIME_BETWEEN_FLASHES
		lastFlashTime = System.currentTimeMillis();
	}

	private void stopFocusFlashing() {
		flashTimer.stop();
	}

	/** Allows "stalled" focus flashing to take place */
	private void resetFocusFlashing() {
		// this will allow flashing to continue, as it resets the timeout period
		lastFlashTime = -getMinimumTimeBetweenFlashes();
	}

	public boolean isEditable() {
		return textField.isEditable();
	}

	public void setEditable(boolean b) {
		textField.setEditable(b);
		updateBackgroundColor();
	}

	private void updateBackgroundColor() {
		// this is purposely done here (before the isEditable() check below) in order to make
		// sure that the default color has been properly initialized
		Color defaultBackgroundColor = getDefaultBackgroundColor();

		Color bgColor = UNEDITABLE_BACKGROUND_COLOR;
		if (isEditable() && isEnabled()) {
			bgColor = hasText ? FILTERED_BACKGROUND_COLOR : defaultBackgroundColor;
		}

		doSetBackground(bgColor);
	}

	private void contrastBackground() {
		Color contrastColor = FLASH_BACKGROUND_COLOR;
		if (textField.getBackground() == FLASH_BACKGROUND_COLOR) {
			contrastColor = FILTERED_BACKGROUND_COLOR;
		}
		doSetBackground(contrastColor);
	}

	public String getText() {
		return textField.getText();
	}

	public void setText(String text) {
		textField.setText(text);
	}

	/**
	 * Adds the listener to this filter field that will be called when the user presses the
	 * enter key.
	 * 
	 * <P>Note: this listener cannot be anonymous, as the underlying storage mechanism may be
	 * using a weak data structure.  This means that you will need to store the listener in
	 * a field inside of your class.
	 * 
	 * @param callback the listener
	 */
	public void addEnterListener(Callback callback) {
		enterListeners.add(callback);
	}

	public void removeEnterListener(Callback callback) {
		enterListeners.remove(callback);
	}

	/**
	 * Adds the filter listener to this filter field that will be called when the filter 
	 * contents change.
	 * 
	 * <P>Note: this listener cannot be anonymous, as the underlying storage mechanism may be
	 * using a weak data structure.  This means that you will need to store the listener in
	 * a field inside of your class.
	 * 
	 * @param l the listener
	 */
	public void addFilterListener(FilterListener l) {
		listeners.add(l);
	}

	public void removeFilterListener(FilterListener l) {
		listeners.remove(l);
	}

	@Override
	public void setEnabled(boolean enabled) {
		textField.setEnabled(enabled);
		updateField(textField.getText().length() > 0);
	}

	@Override
	public boolean isEnabled() {
		return textField.isEnabled();
	}

	@Override
	public void requestFocus() {
		textField.requestFocus();
	}

	private void fireFilterChanged(String text) {
		for (FilterListener l : listeners) {
			l.filterChanged(text);
		}
	}

//==================================================================================================
// Package Methods (these make testing easier)
//==================================================================================================	

	/*package*/ void doSetBackground(Color c) {
		textField.setBackground(c);
	}

	/*package*/ JLabel getClearLabel() {
		return clearLabel;
	}

	/*package*/ Timer getFlashTimer() {
		return flashTimer;
	}

	/*package*/ long getMinimumTimeBetweenFlashes() {
		return MINIMUM_TIME_BETWEEN_FLASHES_MS;
	}

	/*package*/ int getFlashFrequency() {
		return FLASH_FREQUENCY_MS;
	}

	/*package*/ JTextField getTextField() {
		return textField;
	}

	private void updateField(boolean fireEvent) {
		String text = getText();
		hasText = text.length() > 0;

		updateFocusFlashing();

		updateBackgroundColor();

		if (fireEvent) {
			fireFilterChanged(text);
		}

		boolean showFilterButton = hasText && textField.isEnabled();
		updateFilterButton(showFilterButton);
	}

	private void updateFocusFlashing() {
		if (hasText) {
			// no need to flash focus when the user is typing in the filter field
			stallFocusFlashing();
		}
		else {
			stopFocusFlashing();
		}
	}

	private void updateFilterButton(boolean showFilter) {

		// Note: this must be run on the Swing thread.  When the filter button shows itself, 
		//       it requires an AWT lock.  If called from a non-Swing thread, deadlocks!
		SystemUtilities.runIfSwingOrPostSwingLater(() -> {
			if (showFilter) {
				clearLabel.showFilterButton();
			}
			else {
				clearLabel.hideFilterButton();
			}
		});

	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TraversalKeyListener implements KeyListener {
		private final Component component;

		private TraversalKeyListener(Component component) {
			this.component = component;

		}

		@Override
		public void keyPressed(KeyEvent e) {
			// don't care
		}

		@Override
		public void keyReleased(KeyEvent e) {
			if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
				component.requestFocus();
			}
		}

		@Override
		public void keyTyped(KeyEvent e) {
			// don't care
		}
	}

	private class FlashFocusListener extends FocusAdapter {
		@Override
		public void focusGained(FocusEvent e) {
			flashFilterBorder();
		}
	}

	private class FilterDocumentListener implements DocumentListener {
		@Override
		public void changedUpdate(DocumentEvent e) {
			updateField(true);
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			updateField(true);
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			updateField(true);
		}
	}

	private class BackgroundFlashTimer extends Timer implements ActionListener {

		private static final int MAX_FLASH_COUNT = 6;
		int flashCount = 0;

		private BackgroundFlashTimer() {
			super(getFlashFrequency(), null);
			addActionListener(this);
		}

		@Override
		public void actionPerformed(ActionEvent event) {
			if (flashCount < MAX_FLASH_COUNT) {
				contrastBackground();
				flashCount++;
			}
			else {
				stop();
				stallFocusFlashing();
			}
		}

		@Override
		public void restart() {
			flashCount = 0;
			super.restart();
		}

		@Override
		public void stop() {
			super.stop();
			updateBackgroundColor(); // set to the proper non-flashing color
			flashCount = 0;
		}
	}

}
