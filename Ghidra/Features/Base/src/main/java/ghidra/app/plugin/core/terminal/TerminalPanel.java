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
package ghidra.app.plugin.core.terminal;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.ScrollPaneConstants;

import docking.widgets.EventTrigger;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.*;
import docking.widgets.fieldpanel.support.*;
import docking.widgets.indexedscrollpane.IndexedScrollPane;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.app.plugin.core.terminal.TerminalFinder.RegexTerminalFinder;
import ghidra.app.plugin.core.terminal.TerminalFinder.TextTerminalFinder;
import ghidra.app.plugin.core.terminal.vt.*;
import ghidra.app.plugin.core.terminal.vt.VtHandler.*;
import ghidra.app.services.ClipboardService;
import ghidra.util.ColorUtils;
import ghidra.util.Msg;

/**
 * A VT100 terminal emulator in a panel.
 * 
 * <p>
 * This implementation uses Ghidra's {@link FieldPanel} for its rendering, highlighting, cursor
 * positioning, etc. This one follows the same pattern as many other such panels in Ghidra with some
 * exceptions. Namely, it removes all key listeners from the field panel to prevent any accidental
 * local control of the cursor. A terminal emulator defers that entirely to the application. Key
 * strokes are instead sent to the application directly, and it may respond with commands to move
 * the actual cursor. This component also implements the {@link AnsiColorResolver}, as it makes the
 * most sense to declare the various {@link GColor}s here.
 */
public class TerminalPanel extends JPanel implements FieldLocationListener, FieldSelectionListener,
		LayoutListener, AnsiColorResolver {
	protected static final int MAX_TITLE_STACK_SIZE = 20;

	protected static final String DEFAULT_FONT_ID = "font.plugin.terminal";
	protected static final GColor COLOR_BACKGROUND = new GColor("color.bg.plugin.terminal");
	protected static final GColor COLOR_FOREGROUND = new GColor("color.fg.plugin.terminal");
	protected static final GColor COLOR_CURSOR_FOCUSED =
		new GColor("color.cursor.focused.terminal");
	protected static final GColor COLOR_CURSOR_UNFOCUSED =
		new GColor("color.cursor.unfocused.terminal");

	// basic colors
	protected static final GColor COLOR_0_BLACK =
		new GColor("color.fg.plugin.terminal.normal.black");
	protected static final GColor COLOR_1_RED =
		new GColor("color.fg.plugin.terminal.normal.red");
	protected static final GColor COLOR_2_GREEN =
		new GColor("color.fg.plugin.terminal.normal.green");
	protected static final GColor COLOR_3_YELLOW =
		new GColor("color.fg.plugin.terminal.normal.yellow");
	protected static final GColor COLOR_4_BLUE =
		new GColor("color.fg.plugin.terminal.normal.blue");
	protected static final GColor COLOR_5_MAGENTA =
		new GColor("color.fg.plugin.terminal.normal.magenta");
	protected static final GColor COLOR_6_CYAN =
		new GColor("color.fg.plugin.terminal.normal.cyan");
	protected static final GColor COLOR_7_WHITE =
		new GColor("color.fg.plugin.terminal.normal.white");
	protected static final GColor COLOR_0_BRIGHT_BLACK =
		new GColor("color.fg.plugin.terminal.bright.black");
	protected static final GColor COLOR_1_BRIGHT_RED =
		new GColor("color.fg.plugin.terminal.bright.red");
	protected static final GColor COLOR_2_BRIGHT_GREEN =
		new GColor("color.fg.plugin.terminal.bright.green");
	protected static final GColor COLOR_3_BRIGHT_YELLOW =
		new GColor("color.fg.plugin.terminal.bright.yellow");
	protected static final GColor COLOR_4_BRIGHT_BLUE =
		new GColor("color.fg.plugin.terminal.bright.blue");
	protected static final GColor COLOR_5_BRIGHT_MAGENTA =
		new GColor("color.fg.plugin.terminal.bright.magenta");
	protected static final GColor COLOR_6_BRIGHT_CYAN =
		new GColor("color.fg.plugin.terminal.bright.cyan");
	protected static final GColor COLOR_7_BRIGHT_WHITE =
		new GColor("color.fg.plugin.terminal.bright.white");

	protected static final int[] CUBE_STEPS = {
		0, 95, 135, 175, 215, 255
	};

	protected class TerminalFieldPanel extends FieldPanel {
		public TerminalFieldPanel(LayoutModel model) {
			super(model, "Terminal");
			setFieldDescriptionProvider((l, f) -> {
				if (f == null) {
					return null;
				}
				// TODO: Adjust, because lines in the history should not be counted
				return "line " + (l.getIndex().intValue() + 1) + ": " + f.getText();
			});
			paintContext.setFocusedCursorColor(COLOR_CURSOR_FOCUSED);
			paintContext.setNotFocusedCursorColor(COLOR_CURSOR_UNFOCUSED);
			paintContext.setCursorFocused(true);
		}

		@Override
		public void modelSizeChanged(IndexMapper indexMapper) {
			// Avoid centering on cursor
			setCursorOn(false);
			super.modelSizeChanged(indexMapper);
			setCursorOn(true);
		}
	}

	protected FontMetrics metrics;
	protected final TerminalLayoutModel model;
	protected final TerminalFieldPanel fieldPanel;
	protected final IndexedScrollPane scroller;

	protected boolean fixedSize = false;
	protected String title;
	protected final Deque<String> titleStack = new LinkedList<>();

	protected final TerminalProvider provider;
	protected ClipboardService clipboardService;
	protected TerminalClipboardProvider clipboardProvider;
	protected String selectedText;

	protected final ArrayList<TerminalListener> terminalListeners = new ArrayList<>();

	protected VtOutput outputCb;
	protected final TerminalAwtEventEncoder eventEncoder;
	protected final VtResponseEncoder responseEncoder;

	protected TerminalPanel(Charset charset, TerminalProvider provider) {
		this.provider = provider;
		clipboardProvider = new TerminalClipboardProvider(provider);
		Gui.registerFont(this, DEFAULT_FONT_ID);
		this.metrics = getFontMetrics(getFont());
		this.model = new TerminalLayoutModel(this, charset, metrics, this);
		this.fieldPanel = new TerminalFieldPanel(model);
		fieldPanel.addFieldSelectionListener(this);
		fieldPanel.addFieldLocationListener(this);
		fieldPanel.addLayoutListener(this);

		setBackground(COLOR_BACKGROUND);
		// Have to set background before creating scroller;
		fieldPanel.setBackgroundColor(COLOR_BACKGROUND);
		scroller = new IndexedScrollPane(fieldPanel);
		scroller.setBackground(COLOR_BACKGROUND);
		scroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

		scroller.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				if (fixedSize) {
					return;
				}
				resizeTerminalToWindow();
			}
		});

		setPreferredSize(new Dimension(600, 400));

		setLayout(new BorderLayout());
		add(scroller);

		eventEncoder = new TerminalAwtEventEncoder(charset) {
			@Override
			public void generateBytes(ByteBuffer buf) {
				if (outputCb != null) {
					outputCb.out(buf);
				}
			}
		};
		responseEncoder = new VtResponseEncoder(charset) {
			@Override
			protected void generateBytes(ByteBuffer buf) {
				if (outputCb != null) {
					outputCb.out(buf);
				}
			}
		};

		for (KeyListener r : fieldPanel.getKeyListeners()) {
			fieldPanel.removeKeyListener(r);
		}
		fieldPanel.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (provider.isLocalActionKeyBinding(e)) {
					return; // Do not consume, so action can take it
				}
				eventEncoder.keyPressed(e, model.cursorKeyMode, model.keypadMode);
				e.consume();
			}

			@Override
			public void keyTyped(KeyEvent e) {
				eventEncoder.keyTyped(e);
				e.consume();
			}
		});
		fieldPanel.addMouseListener(new MouseListener() {
			@Override
			public void mousePressed(MouseEvent e) {
				/**
				 * NOTE: According to gdb's docs, it's common for terminals to use SHIFT to override
				 * application mouse tracking:
				 * 
				 * https://sourceware.org/gdb/onlinedocs/gdb/TUI-Mouse-Support.html
				 */
				if (model.reportMousePress && !e.isShiftDown()) {
					FieldLocation location = fieldPanel.getLocationForPoint(e.getX(), e.getY());
					eventEncoder.mousePressed(e, location.getIndex().intValueExact(),
						location.getCol());
					e.consume();
				}
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				if (model.reportMousePress && !e.isShiftDown()) {
					FieldLocation location = fieldPanel.getLocationForPoint(e.getX(), e.getY());
					eventEncoder.mouseReleased(e, location.getIndex().intValueExact(),
						location.getCol());
					e.consume();
				}
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				FieldLocation location = fieldPanel.getLocationForPoint(e.getX(), e.getY());
				if (model.reportMousePress && !e.isShiftDown()) {
					e.consume();
					return;
				}
				else if (e.getClickCount() == 2 && e.getButton() == 1) {
					selectWordAt(location, EventTrigger.GUI_ACTION);
					e.consume();
				}
				else if (e.getButton() == 2) {
					String text = getSelectedText();
					if (text == null) {
						return;
					}
					paste(text);
				}
			}

			@Override
			public void mouseEntered(MouseEvent e) {
			}

			@Override
			public void mouseExited(MouseEvent e) {
			}
		});
		fieldPanel.addMouseMotionListener(new MouseMotionListener() {
			@Override
			public void mouseDragged(MouseEvent e) {
				if (model.reportMousePress && !e.isShiftDown()) {
					// TODO: This is not stopping the field selection
					e.consume();
					return;
				}
			}

			@Override
			public void mouseMoved(MouseEvent e) {
			}
		});
		fieldPanel.addMouseWheelListener(new MouseWheelListener() {
			@Override
			public void mouseWheelMoved(MouseWheelEvent e) {
				FieldLocation location = fieldPanel.getLocationForPoint(e.getX(), e.getY());
				if (model.reportMousePress && !e.isShiftDown()) {
					eventEncoder.mouseWheelMoved(e, location.getIndex().intValueExact(),
						location.getCol());
					e.consume();
				}
			}
		});
		fieldPanel.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				if (model.reportFocus) {
					eventEncoder.focusGained();
				}
			}

			@Override
			public void focusLost(FocusEvent e) {
				if (model.reportFocus) {
					eventEncoder.focusLost();
				}
			}
		});
	}

	public void addTerminalListener(TerminalListener listener) {
		terminalListeners.add(listener);
	}

	public void removeTerminalListener(TerminalListener listener) {
		terminalListeners.remove(listener);
	}

	protected void notifyTerminalResized(short cols, short rows) {
		for (TerminalListener l : terminalListeners) {
			try {
				l.resized(cols, rows);
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Error", t.getMessage(), t);
			}
		}
	}

	protected void notifyTerminalRetitled(String title) {
		for (TerminalListener l : terminalListeners) {
			try {
				l.retitled(title);
			}
			catch (Throwable t) {
				Msg.showError(this, null, "Error", t.getMessage(), t);
			}
		}
	}

	@Override
	public void setFont(Font font) {
		super.setFont(font);
		this.metrics = getFontMetrics(font);
		if (model != null) {
			model.setFontMetrics(this.metrics);
		}
	}

	public TerminalFieldPanel getFieldPanel() {
		return fieldPanel;
	}

	@Override
	public void layoutsChanged(List<AnchoredLayout> layouts) {
		/**
		 * Don't just blow away the selection every key stroke; however, don't allow terminal
		 * changes to modify the selected text without the user knowing. That rule is directly
		 * implemented here. If the selected text changes, destroy the selection.
		 */
		if (!Objects.equals(selectedText, getSelectedText())) {
			fieldPanel.clearSelection();
		}
	}

	@Override
	public void selectionChanged(FieldSelection selection, EventTrigger trigger) {
		selectedText = getSelectedText();
		clipboardProvider.selectionChanged(selection);
	}

	@Override
	public void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger) {
		/**
		 * Prevent the user from doing this. Cursor location is controlled by pty. While we've
		 * prevented key strokes from causing this, we've not prevented mouse clicks from doing it.
		 * Next best thing is to just move it back.
		 */
		if (trigger == EventTrigger.GUI_ACTION) {
			placeCursor(false);
		}
	}

	/**
	 * Select the whole word at the given location.
	 * 
	 * <p>
	 * This is used for double-click to select the whole word.
	 * 
	 * @param location the cursor's location
	 * @param trigger the cause of the selection
	 */
	public void selectWordAt(FieldLocation location, EventTrigger trigger) {
		BigInteger index = location.getIndex();
		TerminalLayout layout = model.getLayout(index);
		if (layout == null) {
			return;
		}
		int start = Math.min(location.col, layout.line.findWord(location.col, false));
		int end = Math.max(location.col + 1, layout.line.findWord(location.col, true));
		FieldSelection sel = new FieldSelection();
		sel.addRange(new FieldLocation(index, 0, 0, start), new FieldLocation(index, 0, 0, end));
		fieldPanel.setSelection(sel, trigger);
	}

	/**
	 * Process the given bytes as application output.
	 * 
	 * <p>
	 * In most circumstances, there is a thread that just reads an output stream, usually from a
	 * pty, and feeds it into this method.
	 * 
	 * @param buffer the buffer
	 */
	public void processInput(ByteBuffer buffer) {
		model.processInput(buffer);
	}

	protected Color resolveDefaultColor(WhichGround ground, boolean reverseVideo) {
		if (ground == WhichGround.BACKGROUND) {
			if (reverseVideo) {
				return COLOR_FOREGROUND;
			}
			return null; // background is already drawn
		}
		if (reverseVideo) {
			return COLOR_BACKGROUND;
		}
		return COLOR_FOREGROUND;
	}

	protected Color resolveStandardColor(AnsiStandardColor standard) {
		return switch (standard) {
			case BLACK -> COLOR_0_BLACK;
			case RED -> COLOR_1_RED;
			case GREEN -> COLOR_2_GREEN;
			case YELLOW -> COLOR_3_YELLOW;
			case BLUE -> COLOR_4_BLUE;
			case MAGENTA -> COLOR_5_MAGENTA;
			case CYAN -> COLOR_6_CYAN;
			case WHITE -> COLOR_7_WHITE;
		};
	}

	protected Color resolveIntenseColor(AnsiIntenseColor intense) {
		return switch (intense) {
			case BLACK -> COLOR_0_BRIGHT_BLACK;
			case RED -> COLOR_1_BRIGHT_RED;
			case GREEN -> COLOR_2_BRIGHT_GREEN;
			case YELLOW -> COLOR_3_BRIGHT_YELLOW;
			case BLUE -> COLOR_4_BRIGHT_BLUE;
			case MAGENTA -> COLOR_5_BRIGHT_MAGENTA;
			case CYAN -> COLOR_6_BRIGHT_CYAN;
			case WHITE -> COLOR_7_BRIGHT_WHITE;
		};
	}

	protected Color resolve216Color(Ansi216Color cube) {
		return ColorUtils.getColor(CUBE_STEPS[cube.r()], CUBE_STEPS[cube.g()],
			CUBE_STEPS[cube.b()]);
	}

	protected Color resolveGrayscaleColor(AnsiGrayscaleColor gray) {
		return ColorUtils.getColor(gray.v() * 10 + 8);
	}

	protected Color resolve24BitColor(Ansi24BitColor rgb) {
		return ColorUtils.getColor(rgb.r(), rgb.g(), rgb.b());
	}

	@Override
	public Color resolveColor(AnsiColor color, WhichGround ground, Intensity intensity,
			boolean reverseVideo) {
		if (color == AnsiDefaultColor.INSTANCE) {
			return resolveDefaultColor(ground, reverseVideo);
		}
		if (color instanceof AnsiStandardColor standard) {
			return resolveStandardColor(standard);
		}
		if (color instanceof AnsiIntenseColor intense) {
			return resolveIntenseColor(intense);
		}
		if (color instanceof Ansi216Color cube) {
			return resolve216Color(cube);
		}
		if (color instanceof AnsiGrayscaleColor gray) {
			return resolveGrayscaleColor(gray);
		}
		if (color instanceof Ansi24BitColor rgb) {
			return resolve24BitColor(rgb);
		}
		throw new AssertionError();
	}

	public void setClipboardService(ClipboardService clipboardService) {
		if (this.clipboardService == clipboardService) {
			return;
		}
		if (this.clipboardService != null) {
			this.clipboardService.deRegisterClipboardContentProvider(clipboardProvider);
		}
		this.clipboardService = clipboardService;
		if (this.clipboardService != null) {
			this.clipboardService.registerClipboardContentProvider(clipboardProvider);
		}
	}

	/**
	 * Set the callback for application input, i.e., terminal output
	 * 
	 * <p>
	 * In most circumstances, the bytes are sent to an input stream, usually from a pty.
	 * 
	 * @param outputCb the callback
	 */
	public void setOutputCallback(VtOutput outputCb) {
		this.outputCb = outputCb;
	}

	protected void placeCursor(boolean scroll) {
		int scrollBack = model.getScrollBackSize();
		fieldPanel.setCursorPosition(BigInteger.valueOf(model.getCursorRow() + scrollBack), 0, 0,
			model.getCursorColumn());
		if (scroll) {
			fieldPanel.scrollTo(new FieldLocation(model.resetCursorBottom() + scrollBack));
		}
	}

	protected void saveTitle() {
		titleStack.push(title);
		if (titleStack.size() > MAX_TITLE_STACK_SIZE) {
			titleStack.pollLast();
		}
	}

	protected void restoreTitle() {
		notifyTerminalRetitled(title = titleStack.poll());
	}

	protected void setTitle(String title) {
		notifyTerminalRetitled(this.title = title);
	}

	/**
	 * Send the cursor's position to the application
	 * 
	 * @param row the cursor's row
	 * @param col the cursor's column
	 */
	public void reportCursorPos(int row, int col) {
		responseEncoder.reportCursorPos(row, col);
	}

	public void dispose() {
		if (this.clipboardService != null) {
			clipboardService.deRegisterClipboardContentProvider(clipboardProvider);
		}
	}

	/**
	 * Send the given text to the application, as if typed on the keyboard
	 * 
	 * <p>
	 * Note the application may request a mode called "bracketed paste," in which case the text will
	 * be surrounded by special control sequences, allowing the application to distinguish pastes
	 * from manual typing. An application may do this so that an Undo could undo the whole paste,
	 * and not just the last keystroke simulated by the paste.
	 * 
	 * @param text the text
	 */
	public void paste(String text) {
		if (model.bracketedPaste) {
			responseEncoder.reportPasteStart();
		}
		try {
			eventEncoder.sendText(text);
		}
		finally {
			if (model.bracketedPaste) {
				responseEncoder.reportPasteEnd();
			}
		}
	}

	/**
	 * Get the text selected by the user
	 * 
	 * <p>
	 * If the selection is disjoint, this returns null.
	 * 
	 * @return the selected text, or null
	 */
	public String getSelectedText() {
		FieldSelection sel = fieldPanel.getSelection();
		if (sel == null || sel.getNumRanges() != 1) {
			return null;
		}
		return getSelectedText(sel.getFieldRange(0));
	}

	/**
	 * Get the text covered by the given range
	 * 
	 * @param range the range
	 * @return the text
	 */
	public String getSelectedText(FieldRange range) {
		return model.getSelectedText(range);
	}

	/**
	 * Enumerated options available when searching the terminal's buffer
	 */
	public enum FindOptions {
		/**
		 * Make the search case sensitive. If this flag is absent, the search defaults to case
		 * insensitive.
		 */
		CASE_SENSITIVE,
		/**
		 * Allow the search to wrap.
		 */
		WRAP,
		/**
		 * Require the result to be a whole word.
		 */
		WHOLE_WORD,
		/**
		 * Treat the search term as a regular expression instead of literal text.
		 */
		REGEX
	}

	/**
	 * Search the terminal's buffer for the given text.
	 * 
	 * <p>
	 * The start location should be given, so that the search can progress to each successive
	 * result. If no location is given, e.g., because this is the first time the user has searched,
	 * then a default location will be chosen based on the search direction: the start for forward
	 * or the end for backward.
	 * 
	 * @param text the text (or pattern for {@link FindOptions#REGEX})
	 * @param options the search options
	 * @param start the starting location, or null for a default
	 * @param forward true to search forward, false to search backward
	 * @return the range covering the found term, or null if not found
	 */
	public FieldRange find(String text, Set<FindOptions> options, FieldLocation start,
			boolean forward) {
		TerminalFinder finder = options.contains(FindOptions.REGEX)
				? new RegexTerminalFinder(model, start, forward, text, options)
				: new TextTerminalFinder(model, start, forward, text, options);
		return finder.find();
	}

	protected void resizeTerminalToWindow() {
		Rectangle bounds = scroller.getViewportBorderBounds();
		int cols = bounds.width / metrics.charWidth('M');
		int rows = bounds.height / metrics.getHeight();
		resizeTerminal((short) cols, (short) rows);
	}

	protected void resizeTerminal(short cols, short rows) {
		if (model.resizeTerminal(Short.toUnsignedInt(cols), Short.toUnsignedInt(rows))) {
			notifyTerminalResized((short) model.getCols(), (short) model.getRows());
		}
	}

	/**
	 * Set the terminal to a fixed size.
	 * 
	 * <p>
	 * The terminal will no longer respond to the window resizing, and scrollbars are displayed as
	 * needed. If the terminal size changes as a result of this call,
	 * {@link TerminalListener#resized(int, int)} is invoked.
	 * 
	 * @param cols the number of columns
	 * @param rows the number of rows
	 */
	public void setFixedTerminalSize(short cols, short rows) {
		this.fixedSize = true;
		scroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
		scroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		resizeTerminal(cols, rows);
	}

	/**
	 * Set the terminal to fit the window size.
	 * 
	 * <p>
	 * Immediately fit the terminal to the window. It will also respond to the window resizing by
	 * recalculating the rows and columns and adjusting the buffer's contents to fit. Whenever the
	 * terminal size changes {@link TerminalListener#resized(int, int)} is invoked. The bottom
	 * scrollbar is disabled, and the vertical scrollbar is always displayed, to avoid frenetic
	 * horizontal resizing.
	 */
	public void setDynamicTerminalSize() {
		this.fixedSize = false;
		scroller.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scroller.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		resizeTerminalToWindow();
	}

	public int getColumns() {
		return model.getCols();
	}

	public int getRows() {
		return model.getRows();
	}

	public int getCursorColumn() {
		return model.getCursorColumn();
	}

	public int getCursorRow() {
		return model.getCursorRow();
	}
}
