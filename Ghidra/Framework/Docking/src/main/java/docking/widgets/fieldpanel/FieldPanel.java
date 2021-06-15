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
package docking.widgets.fieldpanel;

import static docking.widgets.EventTrigger.INTERNAL_ONLY;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DockingUtils;
import docking.util.GraphicsUtils;
import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.internal.*;
import docking.widgets.fieldpanel.internal.PaintContext;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexScrollListener;
import docking.widgets.indexedscrollpane.IndexedScrollable;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class FieldPanel extends JPanel
		implements IndexedScrollable, LayoutModelListener, ChangeListener {
	public static final int MOUSEWHEEL_LINES_TO_SCROLL = 3;

	private LayoutModel model;

	private boolean repaintPosted;
	private boolean inFocus;

	private BackgroundColorModel backgroundColorModel =
		new DefaultBackgroundColorModel(Color.WHITE);
	private PaintContext paintContext = new PaintContext();

	private AnchoredLayoutHandler layoutHandler;
	private CursorHandler cursorHandler = new CursorHandler();
	private MouseHandler mouseHandler = new MouseHandler();
	private KeyHandler keyHandler = new KeyHandler();
	private HoverHandler hoverHandler;
	private SelectionHandler selectionHandler = new SelectionHandler();
	private boolean horizontalScrollingEnabled = true;

	private FieldLocation cursorPosition = new FieldLocation();
	private FieldSelection selection = new FieldSelection();
	private FieldSelection highlight = new FieldSelection();

	private List<IndexScrollListener> listeners = new ArrayList<>();
	private List<FieldMouseListener> fieldMouseListeners = new ArrayList<>();
	private List<FieldInputListener> inputListeners = new ArrayList<>();
	private List<FieldLocationListener> cursorListeners = new ArrayList<>();
	private List<LayoutListener> layoutListeners = new ArrayList<>();
	private List<ViewListener> viewListeners = new ArrayList<>();
	private List<FieldSelectionListener> selectionListeners = new ArrayList<>();
	private List<FieldSelectionListener> highlightListeners = new ArrayList<>();
	private List<AnchoredLayout> layouts = new ArrayList<>();

	private int currentViewXpos;

	private JViewport viewport;

	public FieldPanel(LayoutModel model) {
		this.model = model;
		model.addLayoutModelListener(this);
		layoutHandler = new AnchoredLayoutHandler(model, getHeight());
		layouts = layoutHandler.positionLayoutsAroundAnchor(BigInteger.ZERO, 0);

		addKeyListener(new FieldPanelKeyAdapter());
		addMouseListener(new FieldPanelMouseAdapter());
		addMouseMotionListener(new FieldPanelMouseMotionAdapter());
		addMouseWheelListener(new BigFieldPanelMouseWheelListener());
		addFocusListener(new FieldPanelFocusListener());

		setDoubleBuffered(false);
		setFocusable(true);

		hoverHandler = new HoverHandler(this);
	}

	@Override
	public void showIndex(BigInteger layoutIndex, int verticalOffset) {
		if (model.getNumIndexes().equals(BigInteger.ZERO)) {
			return;
		}
		if (!layouts.isEmpty()) {
			AnchoredLayout layout = layouts.get(0);
			if (layout.getIndex().equals(layoutIndex) && layout.getYPos() == verticalOffset) {
				return;
			}
		}
		layouts = layoutHandler.positionLayoutsAroundAnchor(layoutIndex, verticalOffset);
		notifyScrollListenerViewChangedAndRepaint();
	}

	public void scrollView(int viewAmount) {
		layouts = layoutHandler.shiftView(viewAmount);
		notifyScrollListenerViewChangedAndRepaint();
	}

	public void scrollTo(FieldLocation fieldLocation) {
		doScrollTo(fieldLocation);
	}

	public void center(FieldLocation location) {
		int offset = getOffset(location);
		scrollView(offset - getHeight() / 2);
		repaint();
	}

	/**
	 * Makes sure the location is completely visible on the screen. If it already is visible, this
	 * routine will do nothing. If the location is above the screen (at an index less than the first
	 * line on the screen), the view will be scrolled such that the location will appear at the top
	 * of the screen. If the location is below the screen, the view will be scrolled such that the
	 * location will appear at the bottom the screen. The layouts[] array will be updated to reflect
	 * the current view.
	 */
	private void doScrollTo(FieldLocation location) {
		if (layouts.isEmpty()) {
			return;
		}
		BigInteger locationIndex = location.getIndex();
		if (layouts.get(0).getIndex().compareTo(locationIndex) > 0) {
			showIndex(locationIndex, 0);
		}
		else if (layouts.get(layouts.size() - 1).getIndex().compareTo(locationIndex) < 0) {
			showIndex(locationIndex, getHeight() - 1);
		}

		AnchoredLayout layout = findLayoutOnScreen(locationIndex);

		if (layout == null) {
			layout = findClosestLayoutOnScreen(locationIndex);
			if (layout == null) {
				return;
			}
			locationIndex = layout.getIndex();
			location.setIndex(locationIndex);
		}

		Rectangle locationRect =
			layout.getCursorRect(location.fieldNum, location.row, location.col);

		JViewport vp = getViewport();
		if (vp != null) {
			// translate cursor rectangle to views coordinate system. (normally this has
			// no effect except when the view consists of a panel containing multiple field
			// panels, i.e. byte viewer)
			Rectangle r =
				SwingUtilities.convertRectangle(FieldPanel.this, locationRect, getParent());
			locationRect.x = r.x;
			// Unusual Code Alert!:
			// We are artificially making the cursor bigger here so that we will have padding
			// in the left and right edges of the screen as the user cursors around (4226).
			locationRect.x = Math.max(0, locationRect.x - 15);
			locationRect.width += 30;

			Rectangle viewRect = vp.getViewRect();
			if (viewRect.width > 0 && viewRect.height > 0) {
				if (locationRect.x < viewRect.x) {
					vp.setViewPosition(new Point(locationRect.x, viewRect.y));
				}
				else if (locationRect.x + locationRect.width > viewRect.x + viewRect.width) {
					vp.setViewPosition(new Point(
						locationRect.x + locationRect.width - viewRect.width, viewRect.y));
				}
			}
		}

		if (locationRect.y < 0) {
			scrollView(locationRect.y);
		}
		else if (locationRect.y + locationRect.height > getHeight()) {
			scrollView(locationRect.y + locationRect.height - getHeight());
		}
	}

	@Override
	public void scrollLineDown() {
		layouts = layoutHandler.shiftViewDownOneRow();
		notifyScrollListenerViewChangedAndRepaint();
	}

	@Override
	public void scrollLineUp() {
		layouts = layoutHandler.shiftViewUpOneRow();
		notifyScrollListenerViewChangedAndRepaint();
	}

	@Override
	public void scrollPageDown() {
		layouts = layoutHandler.shiftViewDownOnePage();
		notifyScrollListenerViewChangedAndRepaint();
	}

	@Override
	public void scrollPageUp() {
		layouts = layoutHandler.shiftViewUpOnePage();
		notifyScrollListenerViewChangedAndRepaint();
	}

	public void pageUp() {
		doPageUp(EventTrigger.API_CALL);
	}

	public void pageDown() {
		doPageDown(EventTrigger.API_CALL);
	}

	@Override
	public int getHeight(BigInteger index) {
		Layout layout = model.getLayout(index);
		return layout == null ? 0 : layout.getHeight();
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		return model.getIndexAfter(index);
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		return model.getIndexBefore(index);
	}

	@Override
	public BigInteger getIndexCount() {
		return model.getNumIndexes();
	}

	@Override
	public boolean isUniformIndex() {
		return model.isUniform();
	}

	public void cursorUp() {
		cursorHandler.doCursorUp(EventTrigger.API_CALL);
	}

	public void cursorDown() {
		cursorHandler.doCursorDown(EventTrigger.API_CALL);
	}

	public void cursorLeft() {
		cursorHandler.doCursorLeft(EventTrigger.API_CALL);
	}

	public void cursorRight() {
		cursorHandler.doCursorRight(EventTrigger.API_CALL);
	}

	/**
	 * Moves the cursor to the beginning of the line.
	 */
	public void cursorHome() {
		cursorHandler.doCursorHome(EventTrigger.API_CALL);
	}

	public void cursorTopOfFile() {
		doTopOfFile(EventTrigger.API_CALL);
	}

	public void cursorBottomOfFile() {
		doEndOfFile(EventTrigger.API_CALL);
	}

	/**
	 * Moves the cursor to the end of the line.
	 */
	public void cursorEnd() {
		cursorHandler.doCursorEnd(EventTrigger.API_CALL);
	}

	public List<AnchoredLayout> getVisibleLayouts() {
		return new ArrayList<>(layouts);
	}

	/**
	 * Returns true if the given field location is rendered on the screen; false if scrolled
	 * offscreen
	 * 
	 * @param location the location to check
	 * @return true if the location is on the screen
	 */
	public boolean isLocationVisible(FieldLocation location) {
		if (location == null) {
			return false;
		}

		BigInteger locationIndex = location.getIndex();
		for (AnchoredLayout layout : layouts) {
			if (layout.getIndex().equals(locationIndex)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the first visible layout or null if there are no visible layouts
	 * 
	 * @return the first visible layout
	 */
	public AnchoredLayout getVisibleStartLayout() {
		if (layouts.isEmpty()) {
			return null;
		}
		return layouts.get(0);
	}

	/**
	 * Returns the last visible layout or null if there are no visible layouts
	 * 
	 * @return the last visible layout
	 */
	public AnchoredLayout getVisibleEndLayout() {
		if (layouts.isEmpty()) {
			return null;
		}
		return layouts.get(layouts.size() - 1);
	}

	@Override
	public void repaint() {
		repaintPosted = true;
		super.repaint();
	}

	@Override
	public Dimension getPreferredSize() {
		if (viewport == null) {
			viewport = getViewport();
			if (viewport != null) {
				viewport.addChangeListener(this);
			}
		}
		return model.getPreferredViewSize();
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		Point viewPosition = viewport.getViewPosition();
		if (viewPosition.x != currentViewXpos) {
			currentViewXpos = viewPosition.x;
			notifyViewChanged();
		}
	}

	@Override
	public void setBounds(int x, int y, int width, int height) {
		boolean heightChanged = height != getHeight();
		super.setBounds(x, y, width, height);
		if (heightChanged) {
			layouts = layoutHandler.setViewHeight(height);
			notifyScrollListenerViewChangedAndRepaint();
		}
	}

	public void setBlinkCursor(Boolean blinkCursor) {
		cursorHandler.setBlinkCursor(blinkCursor);
	}

	public void enableSelection(boolean b) {
		selectionHandler.enableSelection(b);
	}

	public void setHorizontalScrollingEnabled(boolean enabled) {
		horizontalScrollingEnabled = enabled;
	}

	/**
	 * Returns the default background color.
	 */
	public Color getBackgroundColor() {
		return backgroundColorModel.getDefaultBackgroundColor();
	}

	@Override
	public Color getBackground() {
		if (backgroundColorModel != null) {
			return backgroundColorModel.getDefaultBackgroundColor();
		}
		return super.getBackground();
	}

	/**
	 * Sets the default background color
	 *
	 * @param c the color to use for the background.
	 */
	public void setBackgroundColor(Color c) {
		backgroundColorModel.setDefaultBackgroundColor(c);
		paintContext.setDefaultBackgroundColor(c);
	}

	public Color getBackgroundColor(BigInteger index) {
		return backgroundColorModel.getBackgroundColor(index);
	}

	public void setBackgroundColorModel(BackgroundColorModel model) {
		Color currentDefault = backgroundColorModel.getDefaultBackgroundColor();
		if (model == null) {
			model = new DefaultBackgroundColorModel(currentDefault);
		}
		backgroundColorModel = model;
		backgroundColorModel.setDefaultBackgroundColor(currentDefault);
	}

	/**
	 *
	 * Returns the foreground color.
	 */
	public Color getForegroundColor() {
		return paintContext.getForeground();
	}

	/**
	 * Returns the color used as the background for selected items.
	 */
	public Color getSelectionColor() {
		return paintContext.getSelectionColor();
	}

	/**
	 * Returns the color color used as the background for highlighted items.
	 */
	public Color getHighlightColor() {
		return paintContext.getHighlightColor();
	}

	/**
	 * Returns the current cursor color.
	 */
	public Color getFocusedCursorColor() {
		return paintContext.getFocusedCursorColor();
	}

	public Color getNonFocusCursorColor() {
		return paintContext.getNotFocusedCursorColor();
	}

	public boolean isFocused() {
		return inFocus;
	}

	/**
	 * Cleans up resources when this FieldPanel is no longer needed.
	 */
	public void dispose() {
		mouseHandler.dispose();
		cursorHandler.dispose();

		listeners.clear();
		fieldMouseListeners.clear();
		inputListeners.clear();
		cursorListeners.clear();
		layoutListeners.clear();
		viewListeners.clear();
		selectionListeners.clear();
		highlightListeners.clear();
		layouts.clear();
	}

	/**
	 * Returns the point in pixels of where the cursor is located.
	 */
	public Point getCursorPoint() {
		Rectangle bounds = getCursorBounds();
		if (bounds == null) {
			return new Point(0, 0);
		}
		return bounds.getLocation();
	}

	public Rectangle getCursorBounds() {
		AnchoredLayout layout = findLayoutOnScreen(cursorPosition.getIndex());
		if (layout == null) {
			return null;
		}
		return layout.getCursorRect(cursorPosition.fieldNum, cursorPosition.row,
			cursorPosition.col);
	}

	public FieldLocation getCursorLocation() {
		return new FieldLocation(cursorPosition);
	}

	public Field getCurrentField() {
		return cursorHandler.getCurrentField();
	}

	@Override
	public void addIndexScrollListener(IndexScrollListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeIndexScrollListener(IndexScrollListener listener) {
		listeners.remove(listener);
	}

	public void addFieldSelectionListener(FieldSelectionListener listener) {
		selectionListeners.add(listener);
	}

	public void removeFieldSelectionListener(FieldSelectionListener listener) {
		selectionListeners.remove(listener);
	}

	public void addHighlightListener(FieldSelectionListener listener) {
		selectionListeners.add(listener);
	}

	public void removeHighlightListener(FieldSelectionListener listener) {
		selectionListeners.remove(listener);
	}

	public void addFieldMouseListener(FieldMouseListener listener) {
		fieldMouseListeners.add(listener);
	}

	public void removeFieldMouseListener(FieldMouseListener listener) {
		fieldMouseListeners.remove(listener);
	}

	public void addFieldInputListener(FieldInputListener listener) {
		inputListeners.add(listener);
	}

	public void removeFieldInputListener(FieldInputListener listener) {
		inputListeners.remove(listener);
	}

	public void addFieldLocationListener(FieldLocationListener listener) {
		cursorListeners.add(listener);
	}

	public void removeFieldLocationListener(FieldLocationListener listener) {
		cursorListeners.remove(listener);
	}

	public void addLayoutListener(LayoutListener listener) {
		layoutListeners.add(listener);
	}

	public void removeLayoutListener(LayoutListener listener) {
		layoutListeners.remove(listener);
	}

	public void addViewListener(ViewListener listener) {
		viewListeners.add(listener);
	}

	public void removeViewListener(ViewListener listener) {
		viewListeners.remove(listener);
	}

	/**
	 * Add a new hover provider to be managed.
	 *
	 * @param hoverProvider the new hover provider to be managed.
	 */
	public void setHoverProvider(HoverProvider hoverProvider) {
		hoverHandler.setHoverProvider(hoverProvider);
	}

	/**
	 * Returns the class responsible for triggering popups for this field panel.
	 * 
	 * @return the hover handler.
	 */
	public HoverHandler getHoverHandler() {
		return hoverHandler;
	}

	/**
	 * Returns the Field at the given x,y coordinates. Note the x,y must currently be visible on the
	 * screen or else this method will return null.
	 *
	 * @param x the x mouse coordinate in the component.
	 * @param y the y mouse coordinate in the component.
	 * @param loc will be filled in with the FieldLocation for the given point. Values will be
	 *            undefined if the Field return value is null.
	 * @return Field the Field object the point is over.
	 */
	public Field getFieldAt(int x, int y, FieldLocation loc) {
		Layout layout = findLayoutAt(y);
		if (layout == null) {
			return null;
		}
		layout.setCursor(loc, x, y);
		return layout.getField(loc.fieldNum);
	}

	/**
	 * Clears the selection;
	 */
	public void clearSelection() {
		if (selection.getNumRanges() > 0) {
			selection.clear();
			repaint();
			notifySelectionChanged(EventTrigger.API_CALL);
		}
	}

	/**
	 * Clears the marked area highlight;
	 */
	public void clearHighlight() {
		if (highlight.getNumRanges() > 0) {
			highlight.clear();
			repaint();
			notifyHighlightChanged();
		}
	}

	/**
	 * Sets the cursor color for when this component has focus.
	 *
	 * @param color Color to use for the cursor when this component has keyboard focus.
	 */
	public void setFocusedCursorColor(Color color) {
		paintContext.setFocusedCursorColor(color);
		if (inFocus) {
			paintContext.setCursorFocused(inFocus);
			repaint();
		}
	}

	/**
	 * Sets the cursor color for when this component does not have focus.
	 *
	 * @param color Color to use for the cursor when this component does not have keyboard focus.
	 */
	public void setNonFocusCursorColor(Color color) {
		paintContext.setNotFocusedCursorColor(color);
		if (!inFocus) {
			paintContext.setCursorFocused(inFocus);
			repaint();
		}
	}

	/**
	 * Returns the current selection.
	 */
	public FieldSelection getSelection() {
		return new FieldSelection(selection);
	}

	/**
	 * Returns the current highlight (marked area).
	 */
	public FieldSelection getHighlight() {
		return new FieldSelection(highlight);
	}

	/**
	 * Sets the current selection.
	 *
	 * @param sel the selection to set.
	 */
	public void setSelection(FieldSelection sel) {
		if (!selectionHandler.isSelectionOn()) {
			return;
		}
		selection = new FieldSelection(sel);
		repaint();
		notifySelectionChanged(EventTrigger.API_CALL);
	}

	/**
	 * Sets the current highlight to the specified field selection.
	 *
	 * @param sel the selection to set as the highlight.
	 */
	public void setHighlight(FieldSelection sel) {
		highlight = new FieldSelection(sel);
		repaint();
		notifyHighlightChanged();
	}

	/**
	 * Sets the cursorPosition to the given location.
	 *
	 * @param index the index of the Layout on which to place the cursor.
	 * @param fieldNum the index of the field within its layout on which to place the cursor.
	 * @param row the row within the field to place the cursor.
	 * @param col the col within the row to place the cursor.
	 * @return true if the cursor changed
	 */
	public boolean setCursorPosition(BigInteger index, int fieldNum, int row, int col) {
		return setCursorPosition(index, fieldNum, row, col, EventTrigger.API_CALL);
	}

	// for subclasses to control the event trigger
	/**
	 * Sets the cursorPosition to the given location with the given trigger.
	 * 
	 * @param index the index of the Layout on which to place the cursor.
	 * @param fieldNum the index of the field within its layout on which to place the cursor.
	 * @param row the row within the field to place the cursor.
	 * @param col the col within the row to place the cursor.
	 * @param trigger a caller-specified event trigger.
	 * @return true if the cursor changed
	 */
	public boolean setCursorPosition(BigInteger index, int fieldNum, int row, int col,
			EventTrigger trigger) {
		if (cursorHandler.doSetCursorPosition(index, fieldNum, row, col, trigger)) {
			repaint();
			return true;
		}
		return false;
	}

	/**
	 * Sets the cursor on or off. When the cursor is turned off, there is no visible cursor
	 * displayed on the screen.
	 *
	 * @param cursorOn true turns the cursor on, false turns it off.
	 */
	public void setCursorOn(boolean cursorOn) {
		cursorHandler.setCursorOn(cursorOn);
	}

	/**
	 * Returns the state of the cursor. True if on, false if off.
	 */
	public boolean isCursorOn() {
		return cursorHandler.isCursorOn();
	}

	public void scrollToCursor() {
		cursorHandler.scrollToCursor();
	}

	/**
	 * Sets the cursor to the given Field location and attempts to show that location in the center
	 * of the screen.
	 *
	 * @param index the index of the line to go to.
	 * @param fieldNum the field on the line to go to.
	 * @param row the row in the field to go to.
	 * @param col the column in the field to go to.
	 * @param alwaysCenterCursor if true, centers cursor on screen. Otherwise, only centers cursor
	 *            if cursor is offscreen.
	 */
	public void goTo(BigInteger index, int fieldNum, int row, int col, boolean alwaysCenterCursor) {
		goTo(index, fieldNum, row, col, alwaysCenterCursor, EventTrigger.API_CALL);
	}

	// for subclasses to control the event trigger
	protected void goTo(BigInteger index, int fieldNum, int row, int col,
			boolean alwaysCenterCursor, EventTrigger trigger) {

		if (!cursorHandler.doSetCursorPosition(index, fieldNum, row, col, trigger)) {
			return;
		}

		int beforeOffset = getCursorOffset();
		cursorHandler.scrollToCursor();
		int afterOffset = getCursorOffset();

		if (alwaysCenterCursor || beforeOffset != afterOffset) {
			scrollView(afterOffset - getHeight() / 2);
		}
		repaint();
	}

	/**
	 * Tell the panel to grab the keyboard input focus.
	 */
	public void takeFocus() {
		this.requestFocus();
	}

	/**
	 * Scrolls the view so that the cursor is at the given offset from the top of the screen
	 *
	 * @param offset the pixel distance from the top of the screen at which to scroll the display
	 *            such that the cursor is at that offset.
	 */
	public void positionCursor(int offset) {
		if (offset < 0) {
			offset = 0;
		}
		cursorHandler.scrollToCursor();
		int newOffset = getCursorOffset();
		int scrollAmount = newOffset - offset;
		if (layouts.size() == 0) {
			return;
		}
		scrollView(scrollAmount);
	}

	public boolean isStartDragOK() {
		return !selectionHandler.isInProgress();
	}

	/**
	 * Sets the selection color
	 *
	 * @param color the color to use for selection.
	 */
	public void setSelectionColor(Color color) {
		paintContext.setSelectionColor(color);
	}

	/**
	 * Sets the highlight color
	 *
	 * @param color the color to use for highlights.
	 */
	public void setHighlightColor(Color color) {
		paintContext.setHighlightColor(color);
	}

	/**
	 * Returns a ViewerPosition object which contains the top of screen information. The
	 * ViewerPosition will have the index of the layout at the top of the screen and the yPos of
	 * that layout. For example, if the layout is completely displayed, yPos will be 0. If part of
	 * the layout is off the top off the screen, then yPos will have a negative value (indicating
	 * that it begins above the displayable part of the screen.
	 */
	public ViewerPosition getViewerPosition() {
		if (layouts.size() > 0) {
			return new ViewerPosition(layouts.get(0).getIndex(), 0, layouts.get(0).getYPos());
		}
		return new ViewerPosition(0, 0, 0);
	}

	/**
	 * Scrolls the display to show the layout specified by index at the vertical position specified
	 * by yPos. Generally, the index will be layout at the top of the screen and the yPos will be
	 * &lt;= 0, meaning the layout may be partially off the top of the screen.
	 *
	 * @param index the index of the layout to show at the top of the screen.
	 * @param yPos the position to show the layout.
	 */
	public void setViewerPosition(BigInteger index, int xPos, int yPos) {
		if (index.compareTo(BigInteger.ZERO) >= 0 && index.compareTo(model.getNumIndexes()) < 0) {
			layouts = layoutHandler.positionLayoutsAroundAnchor(index, yPos);
			notifyScrollListenerViewChangedAndRepaint();
		}
		if (xPos != currentViewXpos) {
			if (viewport != null) {
				Point viewPosition = viewport.getViewPosition();
				viewport.setViewPosition(new Point(xPos, viewPosition.y));
			}
		}
	}

	public LayoutModel getLayoutModel() {
		return model;
	}

	/**
	 * Sets the layout model for this field panel
	 *
	 * @param model the layout model to use.
	 */
	public void setLayoutModel(LayoutModel model) {
		invalidate();
		this.model.removeLayoutModelListener(this);
		this.model = model;
		model.addLayoutModelListener(this);
		layoutHandler = new AnchoredLayoutHandler(model, getHeight());
		layouts = layoutHandler.positionLayoutsAroundAnchor(BigInteger.ZERO, 0);
		setCursorPosition(BigInteger.ZERO, 0, 0, 0);
		notifyScrollListenerModelChanged();
		notifyScrollListenerViewChangedAndRepaint();
	}

	@Override
	// BigLayoutModelListener
	public void dataChanged(BigInteger start, BigInteger end) {
		if (layouts.isEmpty()) {
			notifyScrollListenerDataChanged(start, end);
			return;
		}
		Point cursorPoint = getCursorPoint();
		BigInteger firstDisplayedIndex = layouts.get(0).getIndex();
		BigInteger lastDisplayedIndex = layouts.get(layouts.size() - 1).getIndex();

		if (end.compareTo(firstDisplayedIndex) < 0) { // changes are all before currently displayed
			return;
		}
		if (start.compareTo(lastDisplayedIndex) > 0) { // changes are all after currently displayed
			return;
		}
		BigInteger anchorIndex = firstDisplayedIndex;
		int anchorOffset = layouts.get(0).getYPos();

		AnchoredLayout layout = findLayoutOnScreen(cursorPosition.getIndex());

		if (layout != null) {
			// if the cursor is on the screen, reposition relative to cursor and
			// not top of screen.
			anchorIndex = cursorPosition.getIndex();
			anchorOffset = layout.getYPos();
		}
		notifyScrollListenerDataChanged(start, end);

		layouts = layoutHandler.positionLayoutsAroundAnchor(anchorIndex, anchorOffset);

		adjustCursorForDataChange();
		cursorHandler.updateCursor(cursorPoint);
		notifyScrollListenerViewChangedAndRepaint();
	}

	private void adjustCursorForDataChange() {
		BigInteger index = cursorPosition.getIndex();
		if (index == null) {
			return;
		}
		Layout layout = model.getLayout(index);
		if (layout == null) {
			index = getIndexBefore(index);
			if (index != null) {
				cursorPosition.setIndex(index);
			}
		}

	}

	@Override
	// BigLayoutModelListener
	public void modelSizeChanged(IndexMapper indexMapper) {
		BigInteger anchorIndex =
			layouts.isEmpty() ? BigInteger.ZERO : indexMapper.map(layouts.get(0).getIndex());
		int anchorOffset = layouts.isEmpty() ? 0 : layouts.get(0).getYPos();
		Point cursorPoint = getCursorPoint();
		BigInteger cursorIndex = indexMapper.map(cursorPosition.getIndex());
		AnchoredLayout layout = findLayoutOnScreen(cursorIndex);
		if (layout != null) {
			anchorIndex = cursorIndex;
			anchorOffset = layout.getYPos();
		}
		notifyScrollListenerModelChanged();
		layouts = layoutHandler.positionLayoutsAroundAnchor(anchorIndex, anchorOffset);

		updateHighlight(indexMapper);
		cursorHandler.updateCursor(cursorPoint);
		notifyScrollListenerViewChangedAndRepaint();
		invalidate();
	}

	private void updateHighlight(IndexMapper mapper) {
		if (highlight.isEmpty()) {
			return;
		}
		FieldSelection oldHighlight = highlight;
		highlight = new FieldSelection();
		for (FieldRange range : oldHighlight) {
			FieldLocation start = range.getStart();
			FieldLocation end = range.getEnd();
			BigInteger startIndex = mapper.map(start.getIndex());
			BigInteger endIndex = mapper.map(end.getIndex());
			if (startIndex != null && endIndex != null) {
				start.setIndex(startIndex);
				end.setIndex(endIndex);
				highlight.addRange(start, end);
			}
		}
	}

	@Override
	protected void paintComponent(Graphics g) {
		model.flushChanges();
		repaintPosted = false;
		Point start = new Point(0, 0);
		Rectangle paintArea = new Rectangle(start, getSize());

		clearDisplay(g, paintArea);

		for (AnchoredLayout layout : layouts) {
			LayoutBackgroundColorManager colorManager = getLayoutSelectionMap(layout.getIndex());
			paintLayoutBackground(g, paintArea, layout, colorManager);

			// cusorLocation == cursorLoc when cursor is in layout, null
			// otherwise
			FieldLocation cursorLocation =
				cursorHandler.initializeCursorForLayout(layout, colorManager, paintContext);
			try {
				layout.paint(this, g, paintContext, paintArea, colorManager, cursorLocation);
			}
			catch (Exception e) {
				paintExceptionInLayout(g, paintArea, layout, e);
				break;
			}

		}
	}

	public int getOffset(FieldLocation location) {
		Layout layout = findLayoutOnScreen(location.getIndex());
		if (layout == null) {
			return -1;
		}

		Rectangle rect = layout.getCursorRect(location.fieldNum, location.row, location.col);
		if (rect == null) {
			return 0;
		}
		return rect.y;
	}

	/**
	 * Returns the offset of the cursor from the top of the screen
	 */
	public int getCursorOffset() {
		return getOffset(cursorPosition);
	}

	private void notifyScrollListenerViewChangedAndRepaint() {
		BigInteger startIndex = BigInteger.ZERO;
		BigInteger endIndex = startIndex;
		int startY = 0;
		int endY = 0;
		if (!layouts.isEmpty()) {
			AnchoredLayout startLayout = layouts.get(0);
			AnchoredLayout endLayout = layouts.get(layouts.size() - 1);
			startIndex = startLayout.getIndex();
			endIndex = endLayout.getIndex();
			startY = startLayout.getYPos();
			endY = endLayout.getEndY();
		}
		for (IndexScrollListener listener : listeners) {
			listener.indexRangeChanged(startIndex, endIndex, startY, endY);
		}
		for (LayoutListener listener : layoutListeners) {
			listener.layoutsChanged(layouts);
		}
		notifyViewChanged();
		repaint();
	}

	private void notifyScrollListenerModelChanged() {
		for (IndexScrollListener listener : listeners) {
			listener.indexModelChanged();
		}
	}

	private void notifyScrollListenerDataChanged(BigInteger start, BigInteger end) {
		for (IndexScrollListener listener : listeners) {
			listener.indexModelDataChanged(start, end);
		}
	}

	private void notifyViewChanged() {
		if (layouts.isEmpty()) {
			return;
		}
		AnchoredLayout layout = layouts.get(0);
		BigInteger index = layout.getIndex();
		int yOffset = layout.getYPos();
		for (ViewListener listener : viewListeners) {
			listener.viewChanged(this, index, currentViewXpos, yOffset);
		}
	}

	private LayoutBackgroundColorManager getLayoutSelectionMap(BigInteger layoutIndex) {
		Color backgroundColor = backgroundColorModel.getBackgroundColor(layoutIndex);
		Color defaultBackColor = backgroundColorModel.getDefaultBackgroundColor();
		boolean isDefault = backgroundColor.equals(defaultBackColor);
		Color selectionColor = paintContext.getSelectionColor();
		Color highlightColor = paintContext.getHighlightColor();
		Color mixedColor = paintContext.getSelectedHighlightColor();
		if (!isDefault) {
			selectionColor = blend(selectionColor, backgroundColor);
			highlightColor = blend(highlightColor, backgroundColor);
			mixedColor = blend(mixedColor, backgroundColor);
		}

		return LayoutColorMapFactory.getLayoutColorMap(layoutIndex, selection, highlight,
			backgroundColor, selectionColor, highlightColor, mixedColor);
	}

	private Color blend(Color primary, Color secondary) {
		int red = (primary.getRed() * 3 + secondary.getRed()) / 4;
		int green = (primary.getGreen() * 3 + secondary.getGreen()) / 4;
		int blue = (primary.getBlue() * 3 + secondary.getBlue()) / 4;
		return new Color(red, green, blue);
	}

	private void paintLayoutBackground(Graphics g, Rectangle rect, AnchoredLayout layout,
			LayoutBackgroundColorManager layoutSelectionMap) {
		Color layoutBackgroundColor = layoutSelectionMap.getBackgroundColor();
		Color defaultBackgroundColor = backgroundColorModel.getDefaultBackgroundColor();
		if (layoutBackgroundColor != defaultBackgroundColor) {
			g.setColor(layoutBackgroundColor);

			// Hack Alert!: for some clients of the field panel, those that use scaling, there
			// appears an artifact during painting that the height being painted is slightly off.
			// By adding a pixel to the height that problem is fixed. This is not the best
			// solution, but it is simple and doesn't seem to have any ill effects.
			int paintHeight = layout.getHeight() + 1;
			g.fillRect(rect.x, layout.getYPos(), rect.width, paintHeight);
		}
	}

	private void clearDisplay(Graphics g, Rectangle rect) {
		Color backgroundColor = backgroundColorModel.getDefaultBackgroundColor();
		g.setColor(backgroundColor);
		g.fillRect(rect.x, rect.y, rect.width, rect.height);
	}

	private void paintExceptionInLayout(Graphics g, Rectangle r, AnchoredLayout layout,
			Exception e) {
		Color defaultBackgroundColor = backgroundColorModel.getDefaultBackgroundColor();
		g.setColor(defaultBackgroundColor);
		g.fillRect(r.x, layout.getYPos() - layout.getHeight(), r.width, layout.getHeight());
		g.setColor(Color.RED);
		GraphicsUtils.drawString(this, g, "Error Painting Field", r.x, layout.getYPos());
		Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
	}

	private void doPageUp(EventTrigger trigger) {
		Rectangle rect = null;
		Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
		if (layout != null) {
			rect = layout.getCursorRect(cursorPosition.fieldNum, cursorPosition.row,
				cursorPosition.col);
		}
		scrollPageUp();
		int x = rect == null ? 0 : rect.x;
		int y = rect == null ? 0 : rect.y + rect.height / 2;
		cursorHandler.setCursorPos(x, y, trigger);
	}

	private void doPageDown(EventTrigger trigger) {
		Rectangle rect = null;
		Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
		if (layout != null) {
			rect = layout.getCursorRect(cursorPosition.fieldNum, cursorPosition.row,
				cursorPosition.col);
		}
		scrollPageDown();
		int x = rect == null ? 0 : rect.x;
		int y = rect == null ? 0 : rect.y + rect.height / 2;
		cursorHandler.setCursorPos(x, y, trigger);
	}

	private void doTopOfFile(EventTrigger trigger) {
		showIndex(BigInteger.ZERO, 0);
		cursorHandler.setCursorPos(0, 0, trigger);
	}

	private void doEndOfFile(EventTrigger trigger) {
		showIndex(model.getNumIndexes().subtract(BigInteger.ONE), 0);
		if (!layouts.isEmpty()) {
			AnchoredLayout l = layouts.get(layouts.size() - 1);

			// null means don't notify listeners
			cursorHandler.setCursorPos(0, l.getYPos() + l.getHeight() - 1, null);
		}
		cursorHandler.doCursorEnd(trigger);
	}

	public Point getPointForLocation(FieldLocation location) {

		AnchoredLayout layout = findLayoutOnScreen(location.getIndex());
		if (layout == null) {
			return null;
		}
		Rectangle r =
			layout.getCursorRect(location.fieldNum, location.row, location.col);
		return r.getLocation();
	}

	public FieldLocation getLocationForPoint(int x, int y) {
		FieldLocation location = new FieldLocation();
		// delegate to the appropriate layout to do the work
		Layout layout = findLayoutAt(y);
		if (layout != null) {
			layout.setCursor(location, x, y);
		}
		return location;
	}

	private AnchoredLayout findLayoutOnScreen(BigInteger index) {
		for (AnchoredLayout layout : layouts) {
			if (layout.getIndex().equals(index)) {
				return layout;
			}
		}
		return null;

	}

	private AnchoredLayout findClosestLayoutOnScreen(BigInteger index) {
		for (AnchoredLayout layout : layouts) {
			if (layout.getIndex().compareTo(index) >= 0) {
				return layout;
			}
		}
		if (!layouts.isEmpty()) {
			return layouts.get(layouts.size() - 1);
		}
		return null;
	}

	/**
	 * Finds the layout containing the given point.
	 */
	AnchoredLayout findLayoutAt(int y) {
		for (AnchoredLayout layout : layouts) {
			if (layout.contains(y)) {
				return layout;
			}
		}
		return null;
	}

	/**
	 * Notifies all FieldMouselisteners that the cursor position changed.
	 */
	private void notifyFieldMouseListeners(final MouseEvent ev) {
		final FieldLocation loc = new FieldLocation(cursorPosition);
		final Field field = cursorHandler.getCurrentField();
		SystemUtilities.runSwingLater(() -> {
			for (FieldMouseListener l : fieldMouseListeners) {
				l.buttonPressed(loc, field, ev);
			}
		});
	}

	private JViewport getViewport() {
		Container c = getParent();
		while (c != null) {
			if (c instanceof JViewport) {
				return (JViewport) c;
			}
			c = c.getParent();
		}
		return null;
	}

	/**
	 * Notifies all listeners that the selection changed.
	 */
	private void notifySelectionChanged(EventTrigger trigger) {
		FieldSelection currentSelection = new FieldSelection(selection);
		for (FieldSelectionListener l : selectionListeners) {
			l.selectionChanged(currentSelection, trigger);
		}
	}

	/**
	 * Notifies all listeners that the selection changed.
	 */
	private void notifyHighlightChanged() {

		FieldSelection currentSelection = new FieldSelection(highlight);
		for (FieldSelectionListener l : highlightListeners) {
			l.selectionChanged(currentSelection, EventTrigger.API_CALL);
		}
	}

// ==================================================================================================
// Inner Classes
// ==================================================================================================
	public class FieldPanelMouseAdapter extends MouseAdapter {

		@Override
		public void mousePressed(MouseEvent e) {
			hoverHandler.stopHover();
			mouseHandler.mousePressed(e);
			cursorHandler.setCursorPos(e.getX(), e.getY(), EventTrigger.GUI_ACTION);
		}

		@Override
		public void mouseReleased(final MouseEvent e) {
			mouseHandler.mouseReleased(e);
			if (!mouseHandler.didDrag() && !isButton3(e)) {
				notifyFieldMouseListeners(e);
			}
		}

		@Override
		public void mouseExited(MouseEvent evt) {
			hoverHandler.hoverExited();
		}

		public boolean isButton3(MouseEvent e) {
			return e.getButton() == MouseEvent.BUTTON3;
		}
	}

	public class FieldPanelMouseMotionAdapter extends MouseMotionAdapter {
		@Override
		public void mouseDragged(MouseEvent e) {
			hoverHandler.stopHover();
			mouseHandler.mouseDragged(e);
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			hoverHandler.startHover(e);
		}
	}

	interface KeyAction {
		public void handleKeyEvent(KeyEvent event);
	}

	class UpKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkUp(e);
		}
	}

	class DownKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkDown(e);
		}
	}

	class LeftKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkLeft(e);
		}
	}

	class RightKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkRight(e);
		}
	}

	class HomeKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkHome(e);
		}
	}

	class EndKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkEnd(e);
		}
	}

	class PageUpKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkPageUp(e);
		}
	}

	class PageDownKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkPageDown(e);
		}
	}

	class EnterKeyAction implements KeyAction {
		@Override
		public void handleKeyEvent(KeyEvent e) {
			keyHandler.vkEnter(e);
		}
	}

	class FieldPanelKeyAdapter extends KeyAdapter {
		private Map<KeyStroke, KeyAction> actionMap;

		FieldPanelKeyAdapter() {
			actionMap = new HashMap<>();

			//
			// Arrow Keys
			//
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_UP, 0), new UpKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), new DownKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, 0), new LeftKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0), new RightKeyAction());

			//
			// Home/End and Control/Command Home/End
			//
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_HOME, 0), new HomeKeyAction());
			actionMap.put(
				KeyStroke.getKeyStroke(KeyEvent.VK_HOME, DockingUtils.CONTROL_KEY_MODIFIER_MASK),
				new HomeKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_END, 0), new EndKeyAction());
			actionMap.put(
				KeyStroke.getKeyStroke(KeyEvent.VK_END, DockingUtils.CONTROL_KEY_MODIFIER_MASK),
				new EndKeyAction());

			//
			// Page Up/Down
			//
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0), new PageUpKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, 0),
				new PageDownKeyAction());
			actionMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), new EnterKeyAction());

		}

		@Override
		public void keyPressed(KeyEvent e) {
			hoverHandler.stopHover();
			if (e.isAltDown()) {
				return; // let ALT-?? be used for other action key bindings
			}

			// Shift is handled special, so mask it off in the event before getting the action.
			// If the shift is being held, the selection is extended while moving the cursor.
			int keyCode = e.getKeyCode();
			int modifiers =
				e.getModifiers() & ~(InputEvent.SHIFT_DOWN_MASK | InputEvent.SHIFT_MASK);
			KeyEvent maskedEvent = new KeyEvent(e.getComponent(), e.getID(), e.getWhen(), modifiers,
				keyCode, e.getKeyChar(), e.getKeyLocation());

			KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(maskedEvent);
			KeyAction keyAction = actionMap.get(keyStroke);
			if (keyAction != null) {
				e.consume();
				if (!repaintPosted) {
					keyAction.handleKeyEvent(e);
				}
			}
			else if (keyCode == KeyEvent.VK_SHIFT) {
				keyHandler.shiftKeyPressed();
			}
			else {
				cursorHandler.notifyInputListeners(e);
			}
		}

		@Override
		public void keyReleased(KeyEvent e) {
			int keyCode = e.getKeyCode();
			if (keyCode == KeyEvent.VK_SHIFT) {
				keyHandler.shiftKeyReleased();
			}
		}
	}

	public class FieldPanelFocusListener implements FocusListener {
		@Override
		public void focusGained(FocusEvent e) {
			inFocus = true;
			paintContext.setCursorFocused(true);
			cursorHandler.focusGained();
			repaint();
		}

		@Override
		public void focusLost(FocusEvent e) {
			inFocus = false;
			paintContext.setCursorFocused(false);
			cursorHandler.focusLost();

			// this prevents issues when some keybindings trigger new dialogs while selecting
			selectionHandler.endSelectionSequence();
			repaint();
		}
	}

	public class BigFieldPanelMouseWheelListener implements MouseWheelListener {
		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			double wheelRotation = e.getPreciseWheelRotation();

			Layout firstLayout = model.getLayout(BigInteger.ZERO);
			int layoutScrollHt = firstLayout != null //
					? firstLayout.getScrollableUnitIncrement(0, 1)
					: 0;
			int scrollAmount = (int) (wheelRotation * layoutScrollHt * MOUSEWHEEL_LINES_TO_SCROLL);
			if (scrollAmount == 0) {
				return;
			}

			if (hoverHandler.isHoverShowing()) {
				hoverHandler.scroll(scrollAmount);
			}
			else {
				hoverHandler.stopHover();

				if (e.isShiftDown() && horizontalScrollingEnabled) {
					scrollViewHorizontally(scrollAmount);
				}
				else {
					scrollView(scrollAmount);
				}
			}
			e.consume();
		}

		private void scrollViewHorizontally(int scrollAmount) {

			JViewport vp = getViewport();
			if (vp == null) {
				// this will happen for Field Panels not placed inside of scroll panes
				return;
			}

			// horizontal scroll (only move viewport)
			Point pos = vp.getViewPosition();
			vp.setViewPosition(new Point(Math.max(0, pos.x + scrollAmount), pos.y));
		}
	}

	public class MouseHandler implements ActionListener {
		private Timer scrollTimer; // used to generate auto scroll
		private int mouseDownX;
		private int mouseDownY;
		private boolean didDrag;
		private int timerScrollAmount;
		private FieldLocation timerPoint;

		public MouseHandler() {
			scrollTimer = new Timer(100, this);
		}

		public void dispose() {
			scrollTimer.stop();
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			try {
				scrollView(timerScrollAmount);
				if (timerScrollAmount > 0) {
					timerPoint.setIndex(layouts.get(layouts.size() - 1).getIndex());
				}
				else {
					timerPoint.setIndex(layouts.get(0).getIndex());
				}
				selectionHandler.updateSelectionSequence(timerPoint);
			}
			catch (Exception ex) {
				// don't care
			}
		}

		public void mousePressed(MouseEvent e) {
			requestFocus();
			didDrag = false;
			if (e.getButton() != MouseEvent.BUTTON1) {
				return;
			}
			mouseDownX = e.getX();
			mouseDownY = e.getY();

			FieldLocation locationForPoint = getLocationForPoint(mouseDownX, mouseDownY);

			if (isAddToContiguousSelectionActivator(e)) {
				selectionHandler.beginSelectionSequence(cursorPosition);
				selectionHandler.updateSelectionSequence(locationForPoint);
			}
			else if (isAddRemoveDisjointSelectionActivator(e)) {
				AnchoredLayout layout = findLayoutAt(mouseDownY);
				if (layout == null) {
					// the user must have moused over an area without a layout
					return;
				}

				BigInteger index = layout.getIndex();
				BigInteger size = BigInteger.valueOf(layout.getIndexSize());
				FieldLocation start = new FieldLocation(index);
				FieldLocation end = new FieldLocation(index.add(size));
				selectionHandler.beginSelectionSequence(start);
				selectionHandler.setRemoveFromSelection(selection.contains(start));
				selectionHandler.updateSelectionSequence(end);
			}
			else if (!selection.contains(locationForPoint)) {
				selectionHandler.clearSelection();
				selectionHandler.beginSelectionSequence(locationForPoint);
			}
		}

		public boolean didDrag() {
			return didDrag;
		}

		public void mouseDragged(MouseEvent e) {
			if ((e.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) == 0) {
				return;
			}
			int x = e.getX();
			int y = e.getY();
			if (((Math.abs(x - mouseDownX) > 3) || (Math.abs(y - mouseDownY) > 3))) {
				didDrag = true;
				if (selectionHandler.isInProgress()) {
					if (y < 0 || y > getHeight()) {
						timerScrollAmount = y < 0 ? y : y - getHeight();
						timerPoint = new FieldLocation(cursorPosition);
						scrollTimer.start();
					}
					else {
						scrollTimer.stop();
						cursorHandler.setCursorPos(x, y, null); // null means don't notify listeners
						selectionHandler.updateSelectionSequence(cursorPosition);
						repaint();
					}
				}
			}
		}

		public void mouseReleased(MouseEvent e) {
			scrollTimer.stop();
			if (e.getButton() != MouseEvent.BUTTON1) {
				return;
			}

			cursorHandler.setCursorPos(e.getX(), e.getY(), EventTrigger.GUI_ACTION);
			if (didDrag) {
				// Send an event after the drag is finished.  Event are suppressed while dragging,
				// meaning that the above call to setCursorPos() will not have fired an event 
				// because the internal cursor position did not change during the mouse release.
				cursorHandler.notifyCursorChanged(EventTrigger.GUI_ACTION);
			}
			else if (!selectionHandler.isInProgress()) {
				selectionHandler.clearSelection();
			}
			selectionHandler.endSelectionSequence();
		}

		/**
		 * Basically checks if the the "shift" modifier is on and the "control" modifier is not.
		 * Note that "control" is operating system dependent. It is <control> on windows, and
		 * <command> on mac.
		 */
		private boolean isAddToContiguousSelectionActivator(MouseEvent e) {
			return (e.isShiftDown() && !DockingUtils.isControlModifier(e));
		}

		/**
		 * Basically checks if the the "control" modifier is on and the shift modifier is not. Note
		 * that "control" is operating system dependent. It is <control> on windows, and <command>
		 * on mac.
		 */
		private boolean isAddRemoveDisjointSelectionActivator(MouseEvent e) {
			return DockingUtils.isControlModifier(e) && !e.isShiftDown();
		}
	}

	class KeyHandler {

		public void shiftKeyPressed() {
			selectionHandler.beginSelectionSequence(cursorPosition);
		}

		public void shiftKeyReleased() {
			selectionHandler.endSelectionSequence();
		}

		public void vkUp(KeyEvent e) {
			cursorHandler.doCursorUp(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkDown(KeyEvent e) {
			cursorHandler.doCursorDown(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkLeft(KeyEvent e) {
			cursorHandler.doCursorLeft(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkRight(KeyEvent e) {
			cursorHandler.doCursorRight(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkEnd(KeyEvent e) {
			if (DockingUtils.isControlModifier(e)) {
				doEndOfFile(EventTrigger.GUI_ACTION);
			}
			else {
				cursorHandler.doCursorEnd(EventTrigger.GUI_ACTION);
			}
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkHome(KeyEvent e) {
			if (DockingUtils.isControlModifier(e)) {
				doTopOfFile(EventTrigger.GUI_ACTION);
			}
			else {
				cursorHandler.doCursorHome(EventTrigger.GUI_ACTION);
			}
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkPageUp(KeyEvent e) {
			doPageUp(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkPageDown(KeyEvent e) {
			doPageDown(EventTrigger.GUI_ACTION);
			selectionHandler.updateSelectionSequence(cursorPosition);
		}

		public void vkEnter(KeyEvent e) {
			Point pt = getCursorPoint();
			if (pt != null) {
				notifyFieldMouseListeners(new MouseEvent(e.getComponent(), e.getID(), e.getWhen(),
					0, pt.x, pt.y, 2, false, MouseEvent.BUTTON1));
			}
		}

	}

	class SelectionHandler {
		private boolean selectionOn = true;
		private boolean selectionChanged;
		private boolean removeFromSelection;
		private FieldLocation anchorPoint;
		private FieldLocation scrollPoint;

		void beginSelectionSequence(FieldLocation point) {
			if (!selectionOn) {
				return;
			}
			removeFromSelection = false;
			anchorPoint = new FieldLocation(point);
		}

		void setRemoveFromSelection(boolean b) {
			removeFromSelection = b;
		}

		boolean isSelectionOn() {
			return selectionOn;
		}

		void clearSelection() {
			if (!selection.isEmpty()) {
				selection.clear();
				selectionChanged = true;
			}
		}

		boolean isInProgress() {
			return anchorPoint != null;
		}

		void endSelectionSequence() {
			if (!selectionOn) {
				return;
			}
			scrollPoint = null;
			anchorPoint = null;
			if (selectionChanged) {
				notifySelectionChanged(EventTrigger.GUI_ACTION);
				selectionChanged = false;
			}
		}

		void updateSelectionSequence(FieldLocation point) {
			if (!selectionOn || anchorPoint == null) {
				return;
			}
			if (scrollPoint != null) {
				updateSelection(removeFromSelection);
			}
			scrollPoint = new FieldLocation(point);
			updateSelection(!removeFromSelection);
		}

		private void updateSelection(boolean add) {
			if (add) {
				selection.addRange(anchorPoint, scrollPoint);
			}
			else {
				selection.removeRange(anchorPoint, scrollPoint);
			}
			selectionChanged = true;
		}

		public void enableSelection(boolean b) {
			selectionOn = b;
			if (!selectionOn) {
				selection.clear();
			}
		}
	}

	public class CursorHandler {
		private int lastX = 0;
		private boolean cursorOn = true;
		private Field currentField;
		private CursorBlinker cursorBlinker;

		CursorHandler() {
			cursorBlinker = new CursorBlinker(FieldPanel.this);
		}

		public void setBlinkCursor(Boolean blinkCursor) {
			if (blinkCursor && cursorBlinker == null) {
				cursorBlinker = new CursorBlinker(FieldPanel.this);
			}
			else if (!blinkCursor && cursorBlinker != null) {
				cursorBlinker.dispose();
				cursorBlinker = null;
			}
		}

		public boolean isCursorOn() {
			return cursorOn;
		}

		public void setCursorOn(boolean cursorOn) {
			this.cursorOn = cursorOn;

		}

		public void focusLost() {
			if (cursorBlinker != null) {
				cursorBlinker.stop();
			}
		}

		public void focusGained() {
			if (cursorBlinker != null) {
				cursorBlinker.restart();
			}
		}

		public Field getCurrentField() {
			if (currentField == null) {
				AnchoredLayout layout = findLayoutOnScreen(cursorPosition.getIndex());
				if (layout != null) {
					currentField = layout.getField(cursorPosition.getFieldNum());
				}
			}

			return currentField;
		}

		FieldLocation initializeCursorForLayout(AnchoredLayout layout,
				LayoutBackgroundColorManager selectionMap, PaintContext context) {

			if (!cursorOn || !cursorPosition.getIndex().equals(layout.getIndex())) {
				return null;
			}

			if (inFocus && cursorBlinker != null) {
				cursorBlinker.updatePaintArea(layout, cursorPosition);
				context.setCursorHidden(!cursorBlinker.showCursor());
			}

			return cursorPosition;
		}

		/**
		 * Sets the cursor as close to the given point as possible.
		 *
		 * @param x the horizontal coordinate.
		 * @param y the vertical coordinate.
		 */
		private void setCursorPos(int x, int y, EventTrigger trigger) {
			currentField = null;
			// delegate to the appropriate layout to do the work
			Layout layout = findLayoutAt(y);
			if (layout == null) {
				x = 0;
				y = 0;
				layout = findLayoutAt(y);
			}
			if (layout != null) {
				FieldLocation newCursorPosition = new FieldLocation();
				lastX = layout.setCursor(newCursorPosition, x, y);
				currentField = layout.getField(newCursorPosition.fieldNum);
				if (!newCursorPosition.equals(cursorPosition) ||
					EventTrigger.MODEL_CHANGE.equals(trigger)) {
					cursorPosition = newCursorPosition;
					notifyCursorChanged(trigger);
				}
				scrollToCursor();
				repaint();
			}
		}

		private boolean doSetCursorPosition(BigInteger index, int fieldNum, int row, int col,
				EventTrigger trigger) {
			currentField = null;
			if (!cursorOn) {
				return false;
			}

			// Make sure the position is valid
			if ((index.compareTo(BigInteger.ZERO) < 0) ||
				(index.compareTo(model.getNumIndexes()) >= 0)) {
				return false;
			}

			Layout layout = model.getLayout(index);
			if (layout == null) {
				return false;
			}

			if (fieldNum >= layout.getNumFields()) {
				fieldNum = 0;
			}
			currentField = layout.getField(fieldNum);

			if (!currentField.isValid(row, col)) {
				row = 0;
				col = 0;
			}
			cursorPosition.setIndex(index);
			cursorPosition.fieldNum = fieldNum;
			cursorPosition.row = row;
			cursorPosition.col = col;
			lastX = currentField.getX(row, col);
			notifyCursorChanged(trigger);
			return true;
		}

		private boolean doCursorUp(EventTrigger trigger) {
			if (!cursorOn) {
				scrollLineUp();
				return true;
			}
			scrollToCursor();
			AnchoredLayout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout == null) {
				return false;
			}

			if (!layout.cursorUp(cursorPosition, lastX)) {
				if (layout.getIndex().equals(BigInteger.ZERO)) {
					return false;
				}
				int yPos = layout.getYPos() - 1;
				layout = findLayoutAt(yPos);

				if (layout == null) {
					scrollView(yPos);
					yPos = 0;
					layout = findLayoutAt(0);
				}
				if (layout == null) {
					return false;
				}
				layout.setCursor(cursorPosition, lastX, yPos);
			}
			scrollToCursor();
			currentField = layout.getField(cursorPosition.fieldNum);
			repaint();
			notifyCursorChanged(trigger);
			return true;
		}

		private boolean doCursorDown(EventTrigger trigger) {
			if (!cursorOn) {
				scrollLineDown();
				return true;
			}
			scrollToCursor();

			AnchoredLayout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout == null) {
				return false;
			}

			if (!layout.cursorDown(cursorPosition, lastX)) {

				int yPos = layout.getYPos() + layout.getHeight();
				layout = findLayoutAt(yPos);

				if (layout == null) {
					if (yPos >= getHeight()) {
						scrollView(yPos - getHeight() + 1);
						yPos = getHeight();
					}
					layout = findLayoutAt(yPos);
				}
				if (layout == null) {
					return false;
				}
				layout.setCursor(cursorPosition, lastX, yPos);
			}
			currentField = layout.getField(cursorPosition.fieldNum);
			scrollToCursor();
			repaint();
			notifyCursorChanged(trigger);
			return true;
		}

		private void doCursorLeft(EventTrigger trigger) {
			if (!cursorOn) {
				return;
			}
			scrollToCursor();
			Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout != null) {
				int result = layout.cursorLeft(cursorPosition);
				if (result < 0) {
					lastX = Integer.MAX_VALUE;
					if (!doCursorUp(trigger)) {
						doCursorHome(trigger);
					}
				}
				else {
					currentField = layout.getField(cursorPosition.fieldNum);
					lastX = result;
				}

			}
			scrollToCursor();
			repaint();
			notifyCursorChanged(trigger);
		}

		private void doCursorRight(EventTrigger trigger) {
			if (!cursorOn) {
				return;
			}
			scrollToCursor();
			Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout != null) {
				int result = layout.cursorRight(cursorPosition);
				if (result < 0) {
					lastX = 0;
					if (!doCursorDown(trigger)) {
						doCursorEnd(trigger);
					}
				}
				else {
					currentField = layout.getField(cursorPosition.fieldNum);
					lastX = result;
				}
			}
			scrollToCursor();
			repaint();
			notifyCursorChanged(trigger);
		}

		private void doCursorHome(EventTrigger trigger) {
			if (!cursorOn) {
				return;
			}
			scrollToCursor();
			Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout != null) {
				lastX = layout.cursorBeginning(cursorPosition);
				currentField = layout.getField(cursorPosition.fieldNum);
			}
			scrollToCursor();

			repaint();
			notifyCursorChanged(trigger);
		}

		private void doCursorEnd(EventTrigger trigger) {
			if (!cursorOn) {
				return;
			}
			scrollToCursor();
			Layout layout = findLayoutOnScreen(cursorPosition.getIndex());
			if (layout != null) {
				lastX = layout.cursorEnd(cursorPosition);
				currentField = layout.getField(cursorPosition.fieldNum);
			}
			scrollToCursor();

			repaint();
			notifyCursorChanged(trigger);
		}

		/**
		 * Notifies all listeners that the cursor position changed.
		 */
		private void notifyCursorChanged(EventTrigger trigger) {
			if (!cursorOn || trigger == null || trigger == INTERNAL_ONLY) {
				return;
			}

			FieldLocation currentLocation = new FieldLocation(cursorPosition);
			for (FieldLocationListener l : cursorListeners) {
				l.fieldLocationChanged(currentLocation, currentField, trigger);
			}

		}

		public void scrollToCursor() {
			doScrollTo(cursorPosition);
		}

		private void updateCursor(Point cursorPoint) {
			if (!cursorOn) {
				return;
			}

			if (!doSetCursorPosition(cursorPosition.getIndex(), cursorPosition.fieldNum,
				cursorPosition.row, cursorPosition.col, EventTrigger.MODEL_CHANGE)) {
				if (cursorPoint == null) {
					cursorPoint = new Point(0, 0);
				}
				cursorHandler.setCursorPos(cursorPoint.x, cursorPoint.y, EventTrigger.MODEL_CHANGE);
			}
		}

		void dispose() {
			if (cursorBlinker != null) {
				cursorBlinker.dispose();
				cursorBlinker = null;
			}
			currentField = null;
		}

		/**
		 * Notifies all listeners that the cursor position changed.
		 */
		private void notifyInputListeners(KeyEvent ev) {

			if (cursorOn) {
				for (FieldInputListener l : inputListeners) {
					l.keyPressed(ev, cursorPosition.getIndex(), cursorPosition.fieldNum,
						cursorPosition.row, cursorPosition.col, currentField);
				}
			}
		}
	}
}
