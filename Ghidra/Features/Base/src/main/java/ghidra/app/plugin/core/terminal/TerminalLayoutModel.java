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

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.*;

import docking.DockingWindowManager;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldRange;
import ghidra.app.plugin.core.terminal.vt.*;
import ghidra.app.plugin.core.terminal.vt.VtCharset.G;
import ghidra.util.*;

/**
 * The terminal layout model.
 * 
 * <p>
 * This, the buffers, and the parser, comprise the core logic of the terminal emulator. This
 * implements the Ghidra layout model, as well as the handler methods of the VT100 parser. Most of
 * the commands it dispatches to the current buffer. A few others modify some flags, e.g., the
 * handling of mouse events. Another swaps between buffers, etc. This layout model then maps each
 * line to a {@link TerminalLayout}. Unlike some other layout models, this does not create a new
 * layout whenever a line is mutated. Given the frequency with which the terminal contents change,
 * that would generate a decent bit of garbage. The "layout" instead dynamically computes its
 * properties from the mutable line object and paints straight from its buffers.
 */
public class TerminalLayoutModel implements LayoutModel, VtHandler {

	// Buffers for character decoding
	protected final ByteBuffer bb = ByteBuffer.allocate(16);
	protected final CharBuffer cb = CharBuffer.allocate(16);

	protected final CharsetDecoder decoder;

	// States for handling VT-style charsets
	protected final Map<VtCharset.G, VtCharset> vtCharsets = new HashMap<>();
	protected VtCharset.G curVtCharsetG = VtCharset.G.G0;
	protected VtCharset curVtCharset = VtCharset.USASCII;

	// A handle to the panel, so that application commands can manipulate it, e.g., titles,
	// cursor enablement
	protected final TerminalPanel panel;

	// Rendering properties
	protected FontMetrics metrics;
	protected final AnsiColorResolver colors;

	protected final ArrayList<LayoutModelListener> listeners = new ArrayList<>();

	// Layouts and cache for the model
	protected ArrayList<TerminalLayout> layouts = new ArrayList<>();
	protected BigInteger numIndexes = BigInteger.ZERO;
	protected final Map<VtLine, TerminalLayout> layoutCache = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<VtLine, TerminalLayout> eldest) {
			return size() >= bufPrimary.size() + bufAlternate.size();
		}
	};

	// The parser for the actual VT/ANSI control sequences
	protected VtParser parser = new VtParser(this);

	// Screen buffers, primary, alternate, and current
	protected final VtBuffer bufPrimary = new VtBuffer();
	protected final VtBuffer bufAlternate = new VtBuffer();
	protected VtBuffer buffer = bufPrimary;

	// Flags for what's been enabled
	protected boolean showCursor;
	protected boolean bracketedPaste;
	protected boolean reportMousePress;
	protected boolean reportMouseRelease;
	protected boolean reportFocus;
	protected KeyMode cursorKeyMode = KeyMode.NORMAL;
	protected KeyMode keypadMode = KeyMode.NORMAL;

	private Object lock = new Object();

	/**
	 * Create a model
	 * 
	 * @param panel the panel to receive commands from the model's VT/ANSI parser
	 * @param charset the charset for decoding bytes to characters
	 * @param metrics font metrics for the monospaced terminal font
	 * @param colors a resolver for ANSI colors
	 */
	public TerminalLayoutModel(TerminalPanel panel, Charset charset, FontMetrics metrics,
			AnsiColorResolver colors) {
		this.panel = panel;
		this.decoder = charset.newDecoder();
		this.metrics = metrics;
		this.colors = colors;

		bufAlternate.setMaxScrollBack(0);

		buildLayouts();
	}

	@Override
	public void handleFullReset() {
		bb.clear();
		cb.clear();
		decoder.reset();
		vtCharsets.clear();
		curVtCharsetG = VtCharset.G.G0;
		curVtCharset = VtCharset.USASCII;

		layouts.clear();
		layoutCache.clear();
		bufPrimary.reset();
		bufAlternate.reset();
		buffer = bufPrimary;

		bracketedPaste = false;
		reportMousePress = false;
		reportMouseRelease = false;
		reportFocus = false;
		cursorKeyMode = KeyMode.NORMAL;
		keypadMode = KeyMode.NORMAL;
	}

	public void processInput(ByteBuffer buffer) {
		synchronized (lock) {
			parser.process(buffer);
			// TODO: Do this less frequently?
			buildLayouts();
		}
		Swing.runIfSwingOrRunLater(() -> {
			modelChanged();
			panel.placeCursor(true);
		});
	}

	@Override
	public Dimension getPreferredViewSize() {
		// This assumes font is monospaced.
		return new Dimension(buffer.getCols() * metrics.charWidth('M'),
			buffer.getRows() * metrics.getHeight());
	}

	@Override
	public BigInteger getNumIndexes() {
		return numIndexes;
	}

	@Override
	public TerminalLayout getLayout(BigInteger index) {
		synchronized (lock) {
			if (BigInteger.ZERO.compareTo(index) <= 0 && index.compareTo(numIndexes) < 0) {
				return layouts.get(index.intValue());
			}
		}
		return null;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (BigInteger.ZERO.compareTo(index) < 0) {
			return index.subtract(BigInteger.ONE);
		}
		return null;
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger candidate = index.add(BigInteger.ONE);
		if (candidate.compareTo(numIndexes) < 0) {
			return candidate;
		}
		return null;
	}

	protected void addOrSetLayout(int i, TerminalLayout l) {
		if (i < layouts.size()) {
			layouts.set(i, l);
		}
		else {
			assert i == layouts.size();
			layouts.add(l);
		}
	}

	protected TerminalLayout newLayout(VtLine line) {
		return new TerminalLayout(line, metrics, colors);
	}

	protected void buildLayouts() {
		int count = buffer.size();
		numIndexes = BigInteger.valueOf(count);

		buffer.forEachLine(true, (i, y, line) -> {
			if (i < layouts.size()) {
				TerminalLayout layout = layouts.get(i);
				if (layout.line == line) {
					return; // Already checked for line.clearDirty()
				}
				layout = layoutCache.computeIfAbsent(line, this::newLayout);
				layouts.set(i, layout);
			}
			else {
				TerminalLayout layout = layoutCache.computeIfAbsent(line, this::newLayout);
				layouts.add(layout);
			}
		});
	}

	protected void modelChanged() {
		for (LayoutModelListener listener : listeners) {
			try {
				listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Error in Listener", "Error in Listener", e);
			}
		}
	}

	@Override
	public boolean isUniform() {
		return true;
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void flushChanges() {
		// Nothing to do
	}

	private static String dumpBuf(ByteBuffer bb) {
		byte[] data = new byte[bb.remaining()];
		bb.get(bb.position(), data);
		return NumericUtilities.convertBytesToString(data, ":");
	}

	@Override
	public void handleChar(byte b) throws Exception {
		bb.put(b);
		bb.flip();
		CoderResult result = decoder.decode(bb, cb, false);
		if (result.isError()) {
			Msg.error(this, "Error while decoding: " + dumpBuf(bb));
			decoder.reset();
			bb.clear();
		}
		else {
			bb.compact();
		}
		cb.flip();
		while (cb.hasRemaining()) {
			try {
				// A little strange using both unicode and vt charsets....
				buffer.putChar(curVtCharset.mapChar(cb.get()));
				buffer.moveCursorRight(1, true, showCursor);
			}
			catch (Throwable t) {
				Msg.error(this, "Error handling character: " + t, t);
			}
		}
		cb.clear();
	}

	@Override
	public void handleBell() {
		DockingWindowManager.beep();
	}

	@Override
	public void handleBackSpace() {
		buffer.moveCursorLeft(1, true);
	}

	@Override
	public void handleTab() {
		buffer.tab();
	}

	@Override
	public void handleBackwardTab(int n) {
		for (int i = 0; i < n; i++) {
			buffer.tabBack();
		}
	}

	@Override
	public void handleLineFeed() {
		buffer.moveCursorDown(1, true);
	}

	@Override
	public void handleCarriageReturn() {
		buffer.carriageReturn();
	}

	@Override
	public void handleSetCharset(G g, VtCharset cs) {
		vtCharsets.put(g, cs);
		if (curVtCharsetG == g) {
			curVtCharset = cs;
		}
	}

	@Override
	public void handleAltCharset(boolean alt) {
		curVtCharsetG = alt ? VtCharset.G.G1 : VtCharset.G.G0;
		curVtCharset = vtCharsets.getOrDefault(curVtCharsetG, VtCharset.USASCII);
	}

	@Override
	public void handleForegroundColor(AnsiColor fg) {
		buffer.setAttributes(buffer.getAttributes().fg(fg));
	}

	@Override
	public void handleBackgroundColor(AnsiColor bg) {
		buffer.setAttributes(buffer.getAttributes().bg(bg));
	}

	@Override
	public void handleResetAttributes() {
		buffer.setAttributes(VtAttributes.DEFAULTS);
	}

	@Override
	public void handleIntensity(Intensity intensity) {
		buffer.setAttributes(buffer.getAttributes().intensity(intensity));
	}

	@Override
	public void handleFont(AnsiFont font) {
		buffer.setAttributes(buffer.getAttributes().font(font));
	}

	@Override
	public void handleUnderline(Underline underline) {
		buffer.setAttributes(buffer.getAttributes().underline(underline));
	}

	@Override
	public void handleBlink(Blink blink) {
		buffer.setAttributes(buffer.getAttributes().blink(blink));
	}

	@Override
	public void handleReverseVideo(boolean reverse) {
		buffer.setAttributes(buffer.getAttributes().reverseVideo(reverse));
	}

	@Override
	public void handleHidden(boolean hidden) {
		buffer.setAttributes(buffer.getAttributes().hidden(hidden));
	}

	@Override
	public void handleStrikeThrough(boolean strikeThrough) {
		buffer.setAttributes(buffer.getAttributes().strikeThrough(strikeThrough));
	}

	@Override
	public void handleProportionalSpacing(boolean spacing) {
		buffer.setAttributes(buffer.getAttributes().proportionalSpacing(spacing));
	}

	@Override
	public void handleInsertMode(boolean en) {
		// Not seen any use this, but it'll probably need doing later.
		Msg.trace(this, "TODO: handleInsertMode: " + en);
	}

	@Override
	public void handleCursorKeyMode(KeyMode mode) {
		this.cursorKeyMode = mode;
	}

	@Override
	public void handleKeypadMode(KeyMode mode) {
		/**
		 * This will be difficult to implement in Swing/AWT, since the OS and Java will already have
		 * mapped the key, including incorporating the NUMLOCK state. Ignore until it matters.
		 */
		Msg.trace(this, "TODO: handleKeypadMode: " + mode);
	}

	@Override
	public void handleAutoWrapMode(boolean en) {
		System.err.println("TODO: handleAutoWrapMode: " + en);
	}

	@Override
	public void handleBlinkCursor(boolean blink) {
		// Ignore this. FieldPanel seems to support it, but it's inconsistent.
		// It's not a necessary feature, anyway.
		Msg.trace(this, "TODO: handleBlinkCursor: " + blink);
	}

	@Override
	public void handleShowCursor(boolean show) {
		this.showCursor = show;
		if (show) {
			bufPrimary.checkVerticalScroll();
			bufAlternate.checkVerticalScroll();
		}
		panel.fieldPanel.setCursorOn(show);
	}

	@Override
	public void handleReportMouseEvents(boolean press, boolean release) {
		reportMousePress = press;
		reportMouseRelease = release;
	}

	@Override
	public void handleReportFocus(boolean report) {
		reportFocus = report;
	}

	@Override
	public void handleMetaKey(boolean en) {
		Msg.trace(this, "TODO: handleMetaKey: " + en); // Not sure I care
	}

	@Override
	public void handleAltScreenBuffer(boolean alt, boolean clearAlt) {
		VtBuffer newBuffer = alt ? bufAlternate : bufPrimary;
		if (buffer == newBuffer) {
			return;
		}
		if (clearAlt) {
			bufAlternate.erase(Erasure.FULL_DISPLAY);
		}
		buffer = newBuffer;
	}

	@Override
	public void handleBracketedPasteMode(boolean en) {
		this.bracketedPaste = en;
	}

	@Override
	public void handleSaveCursorPos() {
		buffer.saveCursorPos();
	}

	@Override
	public void handleRestoreCursorPos() {
		buffer.restoreCursorPos();
	}

	@Override
	public void handleMoveCursor(Direction direction, int n) {
		switch (direction) {
			case UP:
				buffer.moveCursorUp(n);
				return;
			case DOWN:
				buffer.moveCursorDown(n, false);
				return;
			case FORWARD:
				buffer.moveCursorRight(n, false, showCursor);
				return;
			case BACK:
				buffer.moveCursorLeft(n, false);
				return;
		}
	}

	@Override
	public void handleMoveCursor(int row, int col) {
		buffer.moveCursor(row, col);
	}

	@Override
	public void handleMoveCursorRow(int row) {
		buffer.moveCursor(row, buffer.getCurX());
	}

	@Override
	public void handleMoveCursorCol(int col) {
		buffer.moveCursor(buffer.getCurY(), col);
	}

	@Override
	public void handleReportCursorPos() {
		panel.reportCursorPos(buffer.getCurY(), buffer.getCurX());
	}

	@Override
	public void handleErase(Erasure erasure) {
		buffer.erase(erasure);
	}

	@Override
	public void handleInsertLines(int n) {
		buffer.insertLines(n);
	}

	@Override
	public void handleDeleteLines(int n) {
		buffer.deleteLines(n);
	}

	@Override
	public void handleDeleteCharacters(int n) {
		buffer.deleteChars(n);
	}

	@Override
	public void handleEraseCharacters(int n) {
		buffer.eraseChars(n);
	}

	@Override
	public void handleInsertCharacters(int n) {
		buffer.insertChars(n);
	}

	@Override
	public void handleSetScrollRange(Integer start, Integer end) {
		buffer.setScrollViewport(start, end);
	}

	@Override
	public void handleScrollViewportDown(int n, boolean intoScrollBack) {
		for (int i = 0; i < n; i++) {
			buffer.scrollViewportDown(intoScrollBack);
		}
	}

	@Override
	public void handleScrollViewportUp(int n) {
		for (int i = 0; i < n; i++) {
			buffer.scrollViewportUp();
		}
	}

	@Override
	public void handleSaveIconTitle() {
		// Don't care about "Icon" title
	}

	@Override
	public void handleRestoreIconTitle() {
		// Don't care about "Icon" title
	}

	@Override
	public void handleSaveWindowTitle() {
		panel.saveTitle();
	}

	@Override
	public void handleRestoreWindowTitle() {
		panel.restoreTitle();
	}

	@Override
	public void handleWindowTitle(String title) {
		panel.setTitle(title);
	}

	protected boolean resizeTerminal(int cols, int rows) {
		boolean affected;
		synchronized (lock) {
			affected = buffer.resize(cols, rows);
			bufPrimary.resize(cols, rows);
			bufAlternate.resize(cols, rows);
		}
		if (affected) {
			Swing.runIfSwingOrRunLater(() -> {
				modelChanged();
				panel.placeCursor(true);
			});
		}
		return affected;
	}

	public int getScrollBackSize() {
		return buffer.getScrollBackSize();
	}

	public int getCursorRow() {
		return buffer.getCurY();
	}

	public int getCursorColumn() {
		return buffer.getCurX();
	}

	public int resetCursorBottom() {
		return buffer.resetBottomY();
	}

	public int getCols() {
		return buffer.getCols();
	}

	public int getRows() {
		return buffer.getRows();
	}

	public String getSelectedText(FieldRange range) {
		synchronized (lock) {
			FieldLocation start = range.getStart();
			int startRow = start.getIndex().intValueExact();
			int startCol = start.getCol();

			FieldLocation end = range.getEnd();
			int endRow = end.getIndex().intValueExact();
			int endCol = end.getCol();

			return buffer.getText(startRow, startCol, endRow, endCol, System.lineSeparator());
		}
	}

	public void setFontMetrics(FontMetrics metrics2) {
		layouts.clear();
		layoutCache.clear();
		buildLayouts();
	}

	public void setMaxScrollBackSize(int rows) {
		bufPrimary.setMaxScrollBack(rows);
	}
}
