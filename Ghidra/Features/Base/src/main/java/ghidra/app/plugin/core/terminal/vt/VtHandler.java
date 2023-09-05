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
package ghidra.app.plugin.core.terminal.vt;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.PrimitiveIterator.OfInt;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.Msg;

/**
 * The handler of parsed ANSI VT control sequences
 * 
 * <p>
 * Here are some of the resources where I found useful documentation:
 * 
 * <ul>
 * <li><a href="https://invisible-island.net/xterm/ctlseqs/ctlseqs.html">XTerm Control
 * Sequences</a></li>
 * <li><a href="https://www2.ccs.neu.edu/research/gpc/VonaUtils/vona/terminal/vtansi.htm">ANSI/VT100
 * Terminal Control Escape Sequences</a></li>
 * <li><a href="https://en.wikipedia.org/wiki/ANSI_escape_code">Wikipedia: ANSI escape code</a></li>
 * </ul>
 * 
 * <p>
 * They were incredibly useful, even when experimentation was required to fill in details, because
 * they at least described the sort of behavior I should be looking for. Throughout the referenced
 * documents and within this documentation, the following abbreviations are used for escape
 * sequences:
 * 
 * <table>
 * <tr>
 * <th>Abbreviation</th>
 * <th>Sequence</th>
 * <th>Java String</th>
 * </tr>
 * <tr>
 * <td>{@code ESC}</td>
 * <td>byte 0x1b</td>
 * <td>{@code "\033"}</td>
 * </tr>
 * <tr>
 * <td>{@code CSI}</td>
 * <td>{@code ESC [}</td>
 * <td>{@code "\033["}</td>
 * </tr>
 * <tr>
 * <td>{@code OSC}
 * <td>{@code ESC ]}</td>
 * <td>{@code "\033]"}</td>
 * </tr>
 * <tr>
 * <td>{@code ST}
 * <td>{@code ESC \}</td>
 * <td>{@code "\033\\"}</td>
 * </tr>
 * <tr>
 * <td>{@code BEL}
 * <td>byte 0x07</td>
 * <td>{@code "\007"}</td>
 * </tr>
 * </table>
 * 
 * <p>
 * The separation between the parser and the handler deals in state management. The parser manages
 * state only of the control sequence parser itself, i.e., the current node in the token parsing
 * state machine. The state of the terminal, e.g., the current attributes, cursor position, etc.,
 * are managed by the handler and its delegates.
 * 
 * <p>
 * For example, the Cursor Position sequence is documented as:
 * <p>
 * <tt>CSI <em>n</em> ; <em>m</em> H</tt>
 * <p>
 * Supposing {@code n} is 13 and {@code m} is 40, this sequence would be encoded as the string
 * {@code "\033[13;40H"}. The parser will handle decoding the CSI, parameters, and final byte
 * {@code 'H'}. It will then invoke {@link #handleCsi(ByteBuffer, ByteBuffer, byte)}. The default
 * implementation provided by this interface handles many of the final bytes, including {@code 'H'}.
 * It will thus invoke the abstract {@link #handleMoveCursor(int, int)} method passing 12 and 39.
 * Note that 1 is subtracted from both parameters, because ANSI specifies 1-up indexing while Java
 * lends itself to 0-up indexing.
 * 
 * <p>
 * The XTerm documentation, which is arguably the most thorough, presents the CSI commands
 * alphabetically by the final byte, in ASCII order. For sanity and consistency, we adopt the same
 * ordering in our switch cases.
 */
public interface VtHandler {
	/**
	 * Use for initializing static final byte array fields from an ASCII-encoded string
	 * 
	 * @param str the string
	 * @return the encoded bytes
	 */
	static byte[] ascii(String str) {
		try {
			return str.getBytes("ASCII");
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertionError(e);
		}
	}

	// Various parameters for the 'h' and 'l' final CSI bytes

	public static final byte[] _4 = ascii("4");
	public static final byte[] Q1 = ascii("?1");
	public static final byte[] Q7 = ascii("?7");
	public static final byte[] Q12 = ascii("?12");
	public static final byte[] Q25 = ascii("?25");
	public static final byte[] Q47 = ascii("?47");
	public static final byte[] Q1000 = ascii("?1000");
	public static final byte[] Q1004 = ascii("?1004");
	public static final byte[] Q1034 = ascii("?1034");
	public static final byte[] Q1047 = ascii("?1047");
	public static final byte[] Q1048 = ascii("?1048");
	public static final byte[] Q1049 = ascii("?1049");
	public static final byte[] Q2004 = ascii("?2004");

	/**
	 * An ANSI color specification
	 *
	 * <p>
	 * We avoid going straight to AWT colors, 1) Because it provides better separation between the
	 * terminal logic and the rendering framework, and 2) Because some specifications, e.g., default
	 * background, are better delayed until the renderer has gathered the necessary context to
	 * resolve it. Various enums and records implement this interface to provide the specifcations.
	 */
	public interface AnsiColor {
	}

	/**
	 * A singleton representing the default color
	 *
	 * <p>
	 * The actual color selected will depend on context and use. Most notably, the default color
	 * used for foreground should greatly contrast the default color used for the background.
	 */
	public enum AnsiDefaultColor implements AnsiColor {
		INSTANCE;
	}

	/**
	 * One of the eight standard ANSI colors
	 *
	 * <p>
	 * The actual color may be modified by other SGR attributes, notably {@link Intensity}. For
	 * colors that are described by hue, some thought should be given to how the standard and
	 * intense versions differ. Some palettes may choose a darker color, reserving the brightest for
	 * the intense version. Others may use the brightest, choosing to whiten the intense version.
	 */
	public enum AnsiStandardColor implements AnsiColor {
		/**
		 * Usually the darkest black available. Implementations may select a color softer on the
		 * eyes, depending on use. For foreground, this should likely be true black (0,0,0).
		 */
		BLACK,
		/**
		 * A color whose hue is clearly red.
		 */
		RED,
		/**
		 * A color whose hue is clearly green.
		 */
		GREEN,
		/**
		 * A color whose hue is clearly yellow.
		 */
		YELLOW,
		/**
		 * A color whose hue is clearly blue. For palettes made to display on a dark (but not black)
		 * background, a hue tinted toward cyan is recommended.
		 */
		BLUE,
		/**
		 * A color whose hue is clearly magenta or purple. For palettes made to display on a dark
		 * (but not black) background, a hue tinted toward red is recommended.
		 */
		MAGENTA,
		/**
		 * A color whose hue is clearly cyan.
		 */
		CYAN,
		/**
		 * A relatively bright white, sparing the brightest for intense white.
		 */
		WHITE;

		/**
		 * An unmodifiable list giving all the standard colors
		 */
		public static final List<AnsiStandardColor> ALL = List.of(AnsiStandardColor.values());

		/**
		 * Get the standard color for the given numerical code
		 * 
		 * <p>
		 * For example, the sequence {@code CSI [ 34 m} would use code 4 (blue).
		 * 
		 * @param code the code
		 * @return the color
		 */
		public static AnsiStandardColor get(int code) {
			return ALL.get(code);
		}
	}

	/**
	 * One of the eight ANSI intense colors
	 * 
	 * <p>
	 * Note that intense colors may also be specified using the standard color with the
	 * {@link Intensity#BOLD} attribute, depending on the command sequence.
	 */
	public enum AnsiIntenseColor implements AnsiColor {
		/**
		 * A relatively dark grey, but not true black.
		 */
		BLACK,
		/**
		 * See {@link AnsiStandardColor#RED}, but brighter and/or whiter.
		 */
		RED,
		/**
		 * See {@link AnsiStandardColor#GREEN}, but brighter and/or whiter.
		 */
		GREEN,
		/**
		 * See {@link AnsiStandardColor#YELLOW}, but brighter and/or whiter.
		 */
		YELLOW,
		/**
		 * See {@link AnsiStandardColor#BLUE}, but brighter and/or whiter.
		 */
		BLUE,
		/**
		 * See {@link AnsiStandardColor#MAGENTA}, but brighter and/or whiter.
		 */
		MAGENTA,
		/**
		 * See {@link AnsiStandardColor#CYAN}, but brighter and/or whiter.
		 */
		CYAN,
		/**
		 * Usually the brightest white available.
		 */
		WHITE;

		/**
		 * An unmodifiable list giving all the intense colors
		 */
		public static final List<AnsiIntenseColor> ALL = List.of(AnsiIntenseColor.values());

		/**
		 * Get the intense color for the given numerical code
		 * 
		 * <p>
		 * For example, the sequence {@code CSI [ 94 m} would use code 4 (blue).
		 * 
		 * @param code the code
		 * @return the color
		 */
		public static AnsiIntenseColor get(int code) {
			return ALL.get(code);
		}
	}

	/**
	 * For 8-bit colors, one of the 216 colors from the RGB cube
	 * 
	 * <p>
	 * The r, g, and b fields give the "step" number from 0 to 5, dimmest to brightest.
	 */
	public record Ansi216Color(int r, int g, int b) implements AnsiColor {
	}

	/**
	 * For 8-bit colors, one of the 24 grays
	 * 
	 * <p>
	 * The v field is a value from 0 to 23, 0 being the dimmest, but not true black, and 23 being
	 * the brightest, but not true white.
	 */
	public record AnsiGrayscaleColor(int v) implements AnsiColor {
	}

	/**
	 * A 24-bit color
	 * 
	 * <p>
	 * The r, g, and b fields are values from 0 to 255 dimmest to brightest.
	 */
	public record Ansi24BitColor(int r, int g, int b) implements AnsiColor {
	}

	/**
	 * Modifies the intensity of the character either by color or by font weight.
	 * 
	 * <p>
	 * The renderer may choose a combination of strategies. For example, {@link #NORMAL} may be
	 * rendered using the standard color and bold type. Then {@link #BOLD} would use the intense
	 * color, keeping the bold type; whereas {@link #DIM} would use normal type, keeping the
	 * standard color. Some user configuration may be desired here.
	 */
	public enum Intensity {
		/**
		 * The default intensity
		 */
		NORMAL,
		/**
		 * More intense than {@link #NORMAL}
		 */
		BOLD,
		/**
		 * Less intense than {@link #NORMAL}
		 */
		DIM;
	}

	/**
	 * Modifies the shape of the font
	 */
	public enum AnsiFont {
		/**
		 * The default font
		 */
		NORMAL,
		/**
		 * Slanted or Italic font
		 */
		ITALIC,
		/**
		 * Black letter or Fraktur font (hardly ever used)
		 */
		BLACK_LETTER;
	}

	/**
	 * Places lines under the text
	 */
	public enum Underline {
		/**
		 * The default, no underlines
		 */
		NONE,
		/**
		 * A single underline
		 */
		SINGLE,
		/**
		 * Double underlines
		 */
		DOUBLE;
	}

	/**
	 * Causes text to blink
	 * 
	 * <p>
	 * If implemented, renderers should take care not to irritate the user. One option is to make
	 * {@link #FAST} actually slow, and {@link #SLOW} even slower. Another option is to only blink
	 * for a relatively short period after displaying the text, or perhaps only when the terminal
	 * has focus.
	 */
	public enum Blink {
		/**
		 * The default, no blinking
		 */
		NONE,
		/**
		 * Slow blinking
		 */
		SLOW,
		/**
		 * Fast blinking
		 */
		FAST;
	}

	/**
	 * A direction for relative cursor movement
	 */
	public enum Direction {
		/**
		 * Up a line or row
		 */
		UP,
		/**
		 * Down a line or row
		 */
		DOWN,
		/**
		 * Forward or right a character or column
		 */
		FORWARD,
		/**
		 * Backward or left a character or column
		 */
		BACK;

		/**
		 * Derive the direction from the final byte of the CSI sequence
		 * 
		 * @param b the final byte
		 * @return the direction
		 */
		public static Direction forCsiFinal(byte b) {
			return switch (b) {
				case 'A' -> UP;
				case 'B' -> DOWN;
				case 'C' -> FORWARD;
				case 'D' -> BACK;
				default -> throw new AssertionError();
			};
		}
	}

	/**
	 * An enumeration of erasure specifications
	 */
	public enum Erasure {
		/**
		 * Erase the current line from the cursor to the end, including the cursor's current column
		 */
		TO_LINE_END,
		/**
		 * Erase the current line from the start to the cursor, including the cursor's current
		 * column
		 */
		TO_LINE_START,
		/**
		 * Erase the current line, entirely
		 */
		FULL_LINE,
		/**
		 * Erase the current line from the cursor to the end, including the cursor's current column,
		 * as well as all lines after the current line.
		 */
		TO_DISPLAY_END,
		/**
		 * Erase the current line from the start to the cursor, including the cursor's current
		 * column, as well as all lines before the current line. This excludes the scroll-back
		 * buffer.
		 */
		TO_DISPLAY_START,
		/**
		 * Erase the entire display, except the scroll-back buffer.
		 */
		FULL_DISPLAY,
		/**
		 * Erase the entire display, including the scroll-back buffer.
		 */
		FULL_DISPLAY_AND_SCROLLBACK;

		/**
		 * Derive the erasure specification from the parameter to the Erase Display (ED) control
		 * sequence
		 * 
		 * @param n the parameter
		 * @return the erasure specification
		 */
		public static Erasure fromED(int n) {
			return switch (n) {
				case 0 -> TO_DISPLAY_END;
				case 1 -> TO_DISPLAY_START;
				case 2 -> FULL_DISPLAY;
				case 3 -> FULL_DISPLAY_AND_SCROLLBACK;
				default -> TO_DISPLAY_END;
			};
		}

		/**
		 * Derive the erasure specification from the parameter to the Erase Line (EL) control
		 * sequence
		 * 
		 * @param n the parameter
		 * @return the erasure specification
		 */
		public static Erasure fromEL(int n) {
			return switch (n) {
				case 0 -> TO_LINE_END;
				case 1 -> TO_LINE_START;
				case 2 -> FULL_LINE;
				default -> TO_LINE_END;
			};
		}
	}

	/**
	 * For cursor and keypad, specifies normal or application mode
	 * 
	 * <p>
	 * This affects the codes sent by the terminal.
	 */
	public enum KeyMode {
		NORMAL {
			@Override
			public <T> T choose(T normal, T application) {
				return normal;
			}
		},
		APPLICATION {
			@Override
			public <T> T choose(T normal, T application) {
				return application;
			}
		};

		public abstract <T> T choose(T normal, T application);
	}

	/**
	 * Check if the given buffer's contents are equal to that of the given array
	 * 
	 * @param buf the buffer
	 * @param arr the array
	 * @return true if equal, false otherwise
	 */
	static boolean bufEq(ByteBuffer buf, byte[] arr) {
		return Arrays.equals(buf.array(), buf.position(), buf.limit(), arr, 0, arr.length);
	}

	/**
	 * Render a character and its byte value as a string, used for diagnostics
	 * 
	 * @param b the byte/character to examine
	 * @return the string
	 */
	static String charInfo(byte b) {
		return Character.toString(b) + " (" + Integer.toHexString(b & 0xff) + ")";
	}

	/**
	 * Decode the byte buffer's contents to an ASCII string, used for diagnostics.
	 * 
	 * @param buf the buffer to examine
	 * @return the string
	 */
	static String strBuf(ByteBuffer buf) {
		byte[] arr = new byte[buf.remaining()];
		buf.get(buf.position(), arr);
		try {
			return new String(arr, "ASCII");
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Handle normal character output, i.e., place the character on the display
	 * 
	 * <p>
	 * This excludes control sequences and control characters, e.g., tab, line feed. While we've not
	 * tested, in theory, this can instead buffer the byte for decoding from UTF-8. Still, the
	 * implementation should eagerly decode, rendering characters as soon as they are available.
	 * 
	 * @param b the byte/character
	 * @throws Exception if anything goes wrong
	 */
	void handleChar(byte b) throws Exception;

	/**
	 * Handle a character not part of an escape sequence.
	 * 
	 * <p>
	 * This may include control characters, which are displatched appropriately by this method.
	 * Additionally, this handles any exception thrown by {@link #handleChar(byte)}.
	 * 
	 * @param b the byte/character
	 */
	default void handleCharExc(byte b) {
		try {
			switch (b) {
				case 7:
					handleBell();
					return;
				case 8:
					handleBackSpace();
					return;
				case 9:
					handleTab();
					return;
				case 10:
					handleLineFeed();
					return;
				case 13:
					handleCarriageReturn();
					return;
				case 14:
					handleAltCharset(true);
					return;
				case 15:
					handleAltCharset(false);
					return;
			}
			handleChar(b);
		}
		catch (Exception e) {
			Msg.error(this, "Exception handling terminal character output " + charInfo(b) + ":" + e,
				e);
		}
	}

	/**
	 * Parse a sequence of integers in the form <tt><em>n</em> ; <em>m</em> ;</tt> ....
	 * 
	 * <p>
	 * This is designed to replace the {@link String#split(String)} and
	 * {@link Integer#parseInt(String)} pattern, which should avoid some unnecessary object
	 * creation. Unfortunately, the iterator itself is still an object.... Each parameter is parsed
	 * on demand.
	 * 
	 * @param csiParam the buffer of characters containing the parameters to parse
	 * @return an iterator of integers
	 */
	static OfInt parseCsiInts(ByteBuffer csiParam) {
		ByteBuffer buf = csiParam.duplicate();
		return new OfInt() {
			int next = prepareNext();

			private int prepareNext() {
				if (!buf.hasRemaining()) {
					return -1;
				}
				int value = 0;
				while (buf.hasRemaining()) {
					byte b = buf.get();
					if ('0' <= b && b <= '9') {
						value = value * 10 + (b - '0');
					}
					else if (b == ';' || b == ':') {
						return value;
					}
					else {
						throw new UnknownCsiException();
					}
				}
				return value;
			}

			@Override
			public boolean hasNext() {
				return next != -1;
			}

			@Override
			public int nextInt() {
				int ret = next;
				next = prepareNext();
				return ret;
			}
		};
	}

	/**
	 * An exception for when a CSI sequence is not implemented or recognized
	 */
	class UnknownCsiException extends RuntimeException {
	}

	/**
	 * Handle the parameters for a 'h' or 'l' final byte CSI sequence
	 * 
	 * @param csiParam the parameter buffer
	 * @param en true for 'h', which generally enables things, and false for 'l'
	 */
	default void handleHOrLStuff(ByteBuffer csiParam, boolean en) {
		if (bufEq(csiParam, _4)) {
			handleInsertMode(en);
		}
		else if (bufEq(csiParam, Q1)) {
			handleCursorKeyMode(en ? KeyMode.APPLICATION : KeyMode.NORMAL);
		}
		else if (bufEq(csiParam, Q7)) {
			handleAutoWrapMode(en);
		}
		else if (bufEq(csiParam, Q12)) {
			handleBlinkCursor(en);
		}
		else if (bufEq(csiParam, Q25)) {
			handleShowCursor(en);
		}
		else if (bufEq(csiParam, Q47)) {
			// NB. Same as 1047?
			handleAltScreenBuffer(en, false);
		}
		else if (bufEq(csiParam, Q1000)) {
			handleReportMouseEvents(en, en);
		}
		else if (bufEq(csiParam, Q1004)) {
			handleReportFocus(en);
		}
		else if (bufEq(csiParam, Q1034)) {
			handleMetaKey(en);
		}
		else if (bufEq(csiParam, Q1047)) {
			// NB. Same as 47?
			handleAltScreenBuffer(en, false);
		}
		else if (bufEq(csiParam, Q1048)) {
			if (en) {
				handleSaveCursorPos();
			}
			else {
				handleRestoreCursorPos();
			}
		}
		else if (bufEq(csiParam, Q1049)) {
			// TODO: I'm already using a separate cursor per buffer....
			if (en) {
				handleSaveCursorPos();
				handleAltScreenBuffer(en, true);
			}
			else {
				handleAltScreenBuffer(en, true);
				handleRestoreCursorPos();
			}
		}
		else if (bufEq(csiParam, Q2004)) {
			handleBracketedPasteMode(en);
		}
		else {
			throw new UnknownCsiException();
		}
	}

	/**
	 * Handle XTerm CSI commands that manipulate the window titles
	 * 
	 * @param csiParam the buffer of parameters
	 */
	default void handleWindowManipulation(ByteBuffer csiParam) {
		OfInt bits = parseCsiInts(csiParam);
		if (!bits.hasNext()) {
			throw new UnknownCsiException();
		}
		switch (bits.nextInt()) {
			case 22: {
				switch (bits.nextInt()) {
					case 0: {
						handleSaveIconTitle();
						handleSaveWindowTitle();
						return;
					}
					case 1: {
						handleSaveIconTitle();
						return;
					}
					case 2: {
						handleSaveWindowTitle();
						return;
					}
					default: {
						throw new UnknownCsiException();
					}
				}
			}
			case 23: {
				switch (bits.nextInt()) {
					case 0: {
						handleRestoreIconTitle();
						handleRestoreWindowTitle();
						return;
					}
					case 1: {
						handleRestoreIconTitle();
						return;
					}
					case 2: {
						handleRestoreWindowTitle();
						return;
					}
					default: {
						throw new UnknownCsiException();
					}
				}
			}
			default: {
				throw new UnknownCsiException();
			}
		}
	}

	/**
	 * Handle a CSI sequence
	 * 
	 * @param csiParam the parameter buffer
	 * @param csiInter the intermediate buffer
	 * @param csiFinal the final byte
	 * @throws Exception if anything goes wrong
	 */
	default void handleCsi(ByteBuffer csiParam, ByteBuffer csiInter, byte csiFinal)
			throws Exception {
		try {
			switch (csiFinal) {
				case '@': { // Insert characters
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleInsertCharacters(n);
					return;
				}
				case 'A': // Cursor up
				case 'B': // Cursor down
				case 'C': // Cursor forward
				case 'D': /* Cursor back */ {
					Direction dir = Direction.forCsiFinal(csiFinal);
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleMoveCursor(dir, n);
					return;
				}
				case 'G': { // Cursor character absolute
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleMoveCursorCol(n - 1);
					return;
				}
				case 'H': { // Cursor position
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					int m = bits.hasNext() ? bits.nextInt() : 1;
					handleMoveCursor(n - 1, m - 1);
					return;
				}
				case 'J': { // Erase in display
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 0;
					handleErase(Erasure.fromED(n));
					return;
				}
				case 'K': { // Erase in line
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 0;
					handleErase(Erasure.fromEL(n));
					return;
				}
				case 'L': { // Insert lines
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleInsertLines(n);
					return;
				}
				case 'M': { // Delete lines
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleDeleteLines(n);
					return;
				}
				case 'P': { // Delete characters
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleDeleteCharacters(n);
					return;
				}
				case 'S': { // Scroll up lines
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleScrollLinesUp(n, false);
					return;
				}
				case 'T': { // Scroll down lines
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleScrollLinesDown(n);
					return;
				}
				case 'X': { // Erase characters
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleEraseCharacters(n);
					return;
				}
				case 'Z': { // Cursor backward tabulation
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleBackwardTab(n);
					return;
				}
				case 'c': { // Send Device Attributes
					Msg.trace(this, "TODO: Send Device Attributes");
					return;
				}
				case 'd': { // Line position absolute
					OfInt bits = parseCsiInts(csiParam);
					int n = bits.hasNext() ? bits.nextInt() : 1;
					handleMoveCursorRow(n - 1);
					return;
				}
				case 'h': {
					handleHOrLStuff(csiParam, true);
					return;
				}
				case 'l': {
					handleHOrLStuff(csiParam, false);
					return;
				}
				case 'm': { // Select Graphic Rendition (SGR)
					if (csiParam.hasRemaining()) {
						switch (csiParam.get(csiParam.position())) {
							case '>': // Set key modifier options
								Msg.trace(this, "TODO: Set key modifier options");
								return;
							case '?': // Query key modifier options
								Msg.trace(this, "TODO: Query key modifier options");
								return;
						}
					}
					OfInt bits = parseCsiInts(csiParam);
					if (!bits.hasNext()) {
						handleResetAttributes();
					}
					while (bits.hasNext()) {
						handleSgrAttribute(bits);
					}
					return;
				}
				case 'n': { // Device Status Report
					OfInt bits = parseCsiInts(csiParam);
					if (!bits.hasNext()) {
						throw new UnknownCsiException();
					}
					switch (bits.nextInt()) {
						case 6: // Report Cursor Position
							handleReportCursorPos();
							return;
						case 5: // Status Report (Not implemented)
						default:
							throw new UnknownCsiException();
					}
				}
				case 'p': { // Soft terminal reset
					// TODO: Not sure how/if this should differ from "full" reset
					handleFullReset();
					return;
				}
				case 'r': { // Scroll screen
					OfInt bits = parseCsiInts(csiParam);
					Integer start = bits.hasNext() ? bits.nextInt() - 1 : null;
					Integer end = bits.hasNext() ? bits.nextInt() - 1 : null;
					handleSetScrollRange(start, end);
					return;
				}
				case 's': {
					handleSaveCursorPos();
					return;
				}
				case 't': { // Window manipulation
					handleWindowManipulation(csiParam);
					return;
				}
				case 'u': {
					handleRestoreCursorPos();
					return;
				}
				default: {
					throw new UnknownCsiException();
				}
			}
		}
		catch (UnknownCsiException e) {
			Msg.error(this, "Unknown CSI sequence: param:'" +
				strBuf(csiParam) + "' inter:'" + strBuf(csiInter) + "' final:" +
				charInfo(csiFinal));
		}
		return;
	}

	/**
	 * Handle a CSI sequence, printing any exception
	 * 
	 * @see #handleCsi(ByteBuffer, ByteBuffer, byte)
	 */
	default void handleCsiExc(ByteBuffer csiParam, ByteBuffer csiInter, byte csiFinal) {
		try {
			handleCsi(csiParam, csiInter, csiFinal);
		}
		catch (Exception e) {
			Msg.error(this, "Exception handling terminal CSI sequence", e);
		}
	}

	/**
	 * An exception for when an OSC sequence is not implemented or recognized
	 */
	class UnknownOscException extends RuntimeException {
	}

	/** Pattern for the OSC set window title sequence */
	Pattern PAT_OSC_WINDOW_TITLE = Pattern.compile("0;(?<title>.*)");
	/** Pattern for the OSC color query sequence */
	Pattern PAT_OSC_COLOR_QUERY = Pattern.compile("1[0-9];\\?");
	// TODO: 104;c;c;c... is color reset. I've not implemented setting them, though.
	// No c given = reset all

	// Windows includes the null terminator
	static String truncateAtNull(String str) {
		return str.split("\000", 2)[0];
	}

	/**
	 * Handle an OSC sequence
	 * 
	 * @param oscParam the parameter buffer
	 * @throws Exception if anything goes wrong
	 */
	default void handleOsc(ByteBuffer oscParam) throws Exception {
		try {
			String paramStr = strBuf(oscParam);
			Matcher matcher;

			matcher = PAT_OSC_WINDOW_TITLE.matcher(paramStr);
			if (matcher.matches()) {
				handleWindowTitle(truncateAtNull(matcher.group("title")));
				return;
			}

			matcher = PAT_OSC_COLOR_QUERY.matcher(paramStr);
			if (matcher.matches()) {
				Msg.trace(this, "TODO: OSC Color Query");
				return;
			}
			throw new UnknownOscException();
		}
		catch (UnknownOscException e) {
			Msg.error(this, "Unknown OSC sequence: param:'" + strBuf(oscParam) + "'");
		}
	}

	/**
	 * Handle a OSC sequence, printing any exception
	 * 
	 * @see #handleOsc(ByteBuffer)
	 */
	default void handleOscExc(ByteBuffer oscParam) {
		try {
			handleOsc(oscParam);
		}
		catch (Exception e) {
			Msg.error(this, "Exception handling terminal OSC sequence", e);
		}
	}

	/**
	 * Decode an ANSI color specification
	 * 
	 * @param colorCode the color code (0-7 for standard, 8 for extended, 9 for default
	 * @param bits the parameters for extended colors
	 * @param intensity the current intensity, if applicable
	 * @return the color specification
	 */
	default AnsiColor decodeColor(int colorCode, OfInt bits, Intensity intensity) {
		if (colorCode < 8) {
			return intensity == Intensity.BOLD
					? AnsiIntenseColor.get(colorCode)
					: AnsiStandardColor.get(colorCode);
		}
		if (colorCode == 8) {
			return decodeExtendedColor(bits);
		}
		if (colorCode == 9) {
			return AnsiDefaultColor.INSTANCE;
		}
		Msg.error(this, "Unrecognized color code: " + colorCode);
		return null;
	}

	/**
	 * Decode an extended ANSI color specification
	 * 
	 * @param bits the parameters
	 * @return the color specification
	 */
	default AnsiColor decodeExtendedColor(OfInt bits) {
		if (!bits.hasNext()) {
			Msg.error(this, "Missing color type in extended color code");
			return null;
		}
		int type = bits.nextInt();
		if (type == 5) {
			if (!bits.hasNext()) {
				return null;
			}
			return decode8BitColor(bits.nextInt());
		}
		if (type == 2) {
			if (!bits.hasNext()) {
				return null;
			}
			int r = bits.nextInt();
			if (!bits.hasNext()) {
				return null;
			}
			int g = bits.nextInt();
			if (!bits.hasNext()) {
				return null;
			}
			int b = bits.nextInt();
			return new Ansi24BitColor(r, g, b);
		}
		Msg.error(this, "Unrecognized extended color type: " + type);
		return null;
	}

	/**
	 * Decode the 8-bit ANSI color.
	 * 
	 * <p>
	 * Colors 0-15 are the standard + high-intensity. Colors 16-231 come from a 6x6x6 RGB cube.
	 * Finally, colors 232-255 are 24 steps of gray scale.
	 * 
	 * @param code an 8-bit number
	 * @return the ANSI color
	 */
	default AnsiColor decode8BitColor(int code) {
		if (code < 8) {
			return AnsiStandardColor.get(code);
		}
		if (code < 16) {
			return AnsiIntenseColor.get(code - 8);
		}
		if (code < 232) {
			code -= 16;
			int b = code % 6;
			int g = (code / 6) % 6;
			int r = (code / 36) % 6;
			return new Ansi216Color(r, g, b);
		}
		if (code < 256) {
			return new AnsiGrayscaleColor(code);
		}
		Msg.warn(this, "Invalid 8-bit color code: " + code);
		return null;
	}

	/**
	 * Handle an Select Graphics Rendition attribute (final byte 'm')
	 * 
	 * @param bits the parameters
	 */
	default void handleSgrAttribute(OfInt bits) {
		int code = bits.nextInt();
		if (30 <= code && code < 50) {
			int colorCode = code % 10;
			AnsiColor color = decodeColor(colorCode, bits, Intensity.NORMAL);
			if (code < 40) {
				handleForegroundColor(color);
			}
			else {
				handleBackgroundColor(color);
			}
			return;
		}
		if (90 <= code && code < 110) {
			int colorCode = code % 10;
			AnsiColor color = decodeColor(colorCode, bits, Intensity.BOLD);
			if (code < 100) {
				handleForegroundColor(color);
			}
			else {
				handleBackgroundColor(color);
			}
			return;
		}
		switch (code) {
			case 0:
				handleResetAttributes();
				return;
			case 1:
				handleIntensity(Intensity.BOLD);
				return;
			case 2:
				handleIntensity(Intensity.DIM);
				return;
			case 3:
				handleFont(AnsiFont.ITALIC);
				return;
			case 4:
				handleUnderline(Underline.SINGLE);
				return;
			case 5:
				handleBlink(Blink.SLOW);
				return;
			case 6:
				handleBlink(Blink.FAST);
				return;
			case 7:
				handleReverseVideo(true);
				return;
			case 8:
				handleHidden(true);
				return;
			case 9:
				handleStrikeThrough(true);
				return;
			case 20:
				handleFont(AnsiFont.BLACK_LETTER);
				return;
			case 21:
				handleUnderline(Underline.DOUBLE);
				return;
			case 22:
				handleIntensity(Intensity.NORMAL);
				return;
			case 23:
				handleFont(AnsiFont.NORMAL);
				return;
			case 24:
				handleUnderline(Underline.NONE);
				return;
			case 25:
				handleBlink(Blink.NONE);
				return;
			case 26:
				handleProportionalSpacing(true);
				return;
			case 27:
				handleReverseVideo(false);
				return;
			case 28:
				handleHidden(false);
				return;
			case 29:
				handleStrikeThrough(false);
				return;
			default:
				Msg.warn(this, "Unrecognized SGR attribute: " + code);
				return;
		}
	}

	/**
	 * Alert the user, typically with an audible "ding" or "beep." Alternatively, a gentle visual
	 * alert may be used.
	 */
	void handleBell();

	/**
	 * Handle the backspace control code (0x08), usually just move the cursor left one.
	 */
	void handleBackSpace();

	/**
	 * Handle the tab control code (0x09), usually just move the cursor to the next tab stop.
	 */
	void handleTab();

	/**
	 * Handle the backward tab sequence: move the cursor backward n tab stops.
	 * 
	 * @param n
	 */
	void handleBackwardTab(int n);

	/**
	 * Handle the line feed control code (0x0a), usually just move the cursor down one.
	 */
	void handleLineFeed();

	/**
	 * Handle the carriage return control code (0x0d), usually just move the cursor to the start of
	 * the line.
	 */
	void handleCarriageReturn();

	/**
	 * Handle toggling of the alternate character set.
	 * 
	 * @param alt true for G1, false for G0
	 */
	void handleAltCharset(boolean alt);

	/**
	 * Handle setting of the foreground color
	 * 
	 * @param color the color specification
	 */
	void handleForegroundColor(AnsiColor color);

	/**
	 * Handle setting of the background color
	 * 
	 * @param color the color specification
	 */
	void handleBackgroundColor(AnsiColor color);

	/**
	 * Handle resetting the SGR attributes
	 */
	void handleResetAttributes();

	/**
	 * Handle setting the intensity
	 * 
	 * @param intensity the intensity
	 */
	void handleIntensity(Intensity intensity);

	/**
	 * Handle setting the font
	 * 
	 * @param font the font
	 */
	void handleFont(AnsiFont font);

	/**
	 * Handle setting the underline
	 * 
	 * @param underline the underline
	 */
	void handleUnderline(Underline underline);

	/**
	 * Handle setting the blink
	 * 
	 * @param blink the blink
	 */
	void handleBlink(Blink blink);

	/**
	 * Handle toggling of reverse video
	 * 
	 * <p>
	 * This can be a bit confusing with default colors. In general, this means swapping the
	 * foreground and background color specifications (not inverting the colors or mirroring or some
	 * such). In the case of the default colors, the implementor must be sure to swap the meaning or
	 * "default background" and "default foreground." Furthermore, if "do not paint" is used for
	 * "default background," care must be taken to ensure the foreground is still painted in
	 * reversed mode.
	 * 
	 * @param reverse true to reverse, false otherwise
	 */
	void handleReverseVideo(boolean reverse);

	/**
	 * Handle toggling of the hidden attribute
	 * 
	 * @param hidden true to hide, false to show
	 */
	void handleHidden(boolean hidden);

	/**
	 * Handle setting strike-through
	 * 
	 * @param strikeThrough true to strike, false for no strike
	 */
	void handleStrikeThrough(boolean strikeThrough);

	/**
	 * Handle setting proportional spacing
	 * 
	 * @param spacing true for space proportionally, false otherwise
	 */
	void handleProportionalSpacing(boolean spacing);

	/**
	 * Handle toggling insert mode
	 * 
	 * <p>
	 * In insert mode, characters at and to the right of the cursor are shifted right to make room
	 * for each new character. In replace mode (default), the character at the cursor is replaced
	 * with each new character.
	 * 
	 * @param en true for insert, false for replace (default)
	 */
	void handleInsertMode(boolean en);

	/**
	 * Toggle cursor key mode
	 * 
	 * @param mode the key mode
	 */
	void handleCursorKeyMode(KeyMode mode);

	/**
	 * Toggle keypad mode
	 * 
	 * @param mode the key mode
	 */
	void handleKeypadMode(KeyMode mode);

	/**
	 * Toggle auto-wrap mode
	 * 
	 * @param en true for auto-wrap, false otherwise
	 */
	void handleAutoWrapMode(boolean en);

	/**
	 * Toggle blinking of the cursor
	 * 
	 * <p>
	 * Renderers should take care not to irritate the user. Some possibilities are to blink slowly,
	 * blink only for a short period of time after it moves, and/or blink only when the terminal has
	 * focus.
	 * 
	 * @param blink true to blink, false to leave solid
	 */
	void handleBlinkCursor(boolean blink);

	/**
	 * Toggle display of the cursor
	 * 
	 * @param show true to show the cursor, false to hide it.
	 */
	void handleShowCursor(boolean show);

	/**
	 * Toggle reporting of select mouse events
	 * 
	 * @param press true to report mouse press events, false to not report them
	 * @param release true to report mouse release events, false to not report them
	 */
	void handleReportMouseEvents(boolean press, boolean release);

	/**
	 * Toggle reporting of terminal focus
	 * 
	 * @param report true to report focus gain and loss events, false to not report them
	 */
	void handleReportFocus(boolean report);

	/**
	 * Toggle handling of the meta key
	 * 
	 * @param en true to report the meta modifier in key/mouse events, false to exclude it
	 */
	void handleMetaKey(boolean en);

	/**
	 * Switch to and from the alternate screen buffer, optionally clearing it
	 * 
	 * <p>
	 * This will never clear the normal buffer. If the buffer does not change as a result of this
	 * call, then the alternate buffer is not cleared, even if clearAlt is specified.
	 * 
	 * @param alt true for alternate, false for normal
	 * @param clearAlt if switching, whether to clear the alternate buffer
	 */
	void handleAltScreenBuffer(boolean alt, boolean clearAlt);

	/**
	 * Toggle bracketed paste mode
	 * 
	 * <p>
	 * See the XTerm documentation for motivation, but one example could be applications that have
	 * an undo stack. Without bracketed paste, the application could not recognize the pasted text
	 * as one undoable operation.
	 * 
	 * @param en true to bracket pasted text is special control sequences
	 */
	void handleBracketedPasteMode(boolean en);

	/**
	 * Handle a request to save the cursor position
	 */
	void handleSaveCursorPos();

	/**
	 * Handle a request to restore the previously-saved cursor position
	 */
	void handleRestoreCursorPos();

	/**
	 * Handle a relative cursor movement command
	 * 
	 * @param direction the direction
	 * @param n the number of rows or columns to move
	 */
	void handleMoveCursor(Direction direction, int n);

	/**
	 * Handle an absolute cursor movement command
	 * 
	 * @param row the row (0-up)
	 * @param col the column (0-up)
	 */
	void handleMoveCursor(int row, int col);

	/**
	 * Handle an absolute cursor row movement command
	 * 
	 * <p>
	 * The column should remain the same, i.e., do <em>not</em> reset the column to 0.
	 * 
	 * @param row the row (0-up)
	 */
	void handleMoveCursorRow(int row);

	/**
	 * Handle an absolute cursor column movement command
	 * 
	 * @param col the column (0-up)
	 */
	void handleMoveCursorCol(int col);

	/**
	 * Handle a request to report the cursor position
	 */
	void handleReportCursorPos();

	/**
	 * Handle a request to save the terminal window's icon title
	 * 
	 * <p>
	 * "Icon titles" are a concept from the X Windows system. Do the closest equivalent, if anything
	 * applies at all. The current title is pushed to a stack of limited size.
	 */
	void handleSaveIconTitle();

	/**
	 * Handle a request to save the terminal window's title
	 * 
	 * <p>
	 * Window titles are fairly applicable to all desktop windowing systems. The current title is
	 * pushed to a stack of limited size.
	 */
	void handleSaveWindowTitle();

	/**
	 * Handle a request to restore the terminal window's icon title
	 * 
	 * <p>
	 * The title is set to the one popped from the stack of saved window icon titles.
	 * 
	 * @see #handleSaveIconTitle()
	 */
	void handleRestoreIconTitle();

	/**
	 * Handle a request to restore the terminal window's title
	 * 
	 * <p>
	 * The title is set to the one popped from the stack of saved window titles.
	 * 
	 * @see #handleSaveWindowTitle()
	 */
	void handleRestoreWindowTitle();

	/**
	 * Handle a request to set the terminal window's title
	 * 
	 * @param title the titled
	 */
	void handleWindowTitle(String title);

	/**
	 * Handle a request to erase part of the display
	 * 
	 * @param erasure what, relative to the cursor, to erase
	 */
	void handleErase(Erasure erasure);

	/**
	 * Insert n lines at and below the cursor
	 * 
	 * <p>
	 * Lines within the viewport are shifted down or deleted to make room for the new lines.
	 * 
	 * @param n the number of lines to insert
	 */
	void handleInsertLines(int n);

	/**
	 * Delete n lines at and below the cursor
	 * 
	 * <p>
	 * Lines within the viewport are shifted up, and new lines inserted at the bottom.
	 * 
	 * @param n the number of lines to delete
	 */
	void handleDeleteLines(int n);

	/**
	 * Delete n characters from the current cursor position, and shift the remaining characters
	 * back. If n is one, only the character at the cursor position is deleted. If n is greater,
	 * then additional characters are deleted after (to the right) of the cursor. Consider the
	 * current line contents and cursor position:
	 * 
	 * <pre>
	 * 123456789
	 *     ^
	 * </pre>
	 * 
	 * Deleting 2 characters should result in {@code 1234789}. The character at the cursor (5) and
	 * the following character (6) are deleted. The remaining (789) are all shifted back (left).
	 * 
	 * @param n the number of characters to delete.
	 */
	void handleDeleteCharacters(int n);

	/**
	 * Erase n characters from the current cursor position. In essence, replace the erased
	 * characters with spaces. If n is one, only the character at the cursor position is erased. If
	 * n is greater, then additional characters are erased after (to the right) of the cursor.
	 * 
	 * @param n the number of characters to erase.
	 */
	void handleEraseCharacters(int n);

	/**
	 * Insert n blank characters at the current cursor position, shifting characters right to make
	 * room.
	 * 
	 * @param n the number of characters to insert.
	 */
	void handleInsertCharacters(int n);

	/**
	 * Set the range of rows (viewport) involved in scrolling.
	 * 
	 * <p>
	 * This applies not only to {@link #handleScrollUp()} and {@link #handleScrollDown()}, but also
	 * to when the cursor moves far enough down that the display must scroll. Normally, start is 0
	 * and end is rows-1 (The parser will adjust the 1-up indices to 0-up) so that the entire
	 * display is scrolled. If the cursor moves past end (not just the end of the device, but the
	 * end given here) then the scrolling region must be scrolled. The top line is removed, the
	 * interior lines are moved up, and the bottom line is cleared. If the terminal is resized, the
	 * scroll range is reset to the whole display.
	 * 
	 * @param start the first row (0-up) in the scrolling region. If omitted, the first row of the
	 *            display.
	 * @param end the last row (0-up, inclusive) in the scrolling region. If omitted, the last row
	 *            of the display.
	 */
	void handleSetScrollRange(Integer start, Integer end);

	/**
	 * Scroll the display n lines down, considering only those lines in the scrolling range.
	 * 
	 * <p>
	 * To be unambiguous, this of movement of the viewport. The viewport scrolls down, so the lines
	 * themselves scroll up. The default range is the whole display. The cursor is not moved.
	 * 
	 * @param n the number of lines to scroll
	 * @param intoScrollBack specifies whether the top line may flow into the scroll-back buffer
	 * @see #handleSetScrollRange(Integer, Integer)
	 */
	void handleScrollViewportDown(int n, boolean intoScrollBack);

	/**
	 * Scroll the display n lines up, considering only those lines in the scrolling range.
	 * 
	 * @param n the number of lines to scroll
	 * @see #handleScrollDown()
	 * @see #handleSetScrollRange(Integer, Integer)
	 */
	void handleScrollViewportUp(int n);

	/**
	 * Scroll the lines n slots down, considering only those lines in the scrolling range.
	 * 
	 * <p>
	 * This is equivalent to scrolling the <em>viewport</em> n lines <em>up</em>. This method exists
	 * in attempt to reflect "up" and "down" correctly in the documentation. Unfortunately, the
	 * documentation is not always clear whether we're scrolling the viewport or the lines
	 * themselves.
	 * 
	 * @param n the number of lines to scroll
	 * @see #handleScrollViewportUp(int)
	 */
	default void handleScrollLinesDown(int n) {
		handleScrollViewportUp(n);
	}

	/**
	 * Scroll the lines n slots up, considering only those lines in the scrolling range.
	 * 
	 * <p>
	 * The is equivalent to scrolling the <em>viewport</em> n lines <em>down</em>. This method
	 * exists in attempt to reflect "up" and "down" correctly in the documentation. Unfortunately,
	 * the documentation is not always clear whether we're scrolling the viewport or the lines
	 * themselves.
	 * 
	 * @param n the number of lines to scroll
	 * @param intoScrollBack specifies whether the top line may flow into the scroll-back buffer
	 * @see #handleScrollViewportDown(int)
	 */
	default void handleScrollLinesUp(int n, boolean intoScrollBack) {
		handleScrollViewportDown(n, intoScrollBack);
	}

	/**
	 * Set the charset for a given slot
	 * 
	 * @param g the slot
	 * @param cs the charset
	 */
	void handleSetCharset(VtCharset.G g, VtCharset cs);

	/**
	 * Handle a request to fully reset the terminal
	 * 
	 * <p>
	 * All buffers should be cleared and all state variables, positions, attributes, etc., should be
	 * reset to their defaults.
	 */
	void handleFullReset();
}
