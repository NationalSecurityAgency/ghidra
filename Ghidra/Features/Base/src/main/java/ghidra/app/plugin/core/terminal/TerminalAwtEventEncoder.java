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

import java.awt.event.*;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;

import ghidra.app.plugin.core.terminal.vt.VtHandler.KeyMode;
import ghidra.util.Msg;

/**
 * An encoder which can translate AWT/Swing events into ANSI input codes.
 * 
 * <p>
 * The input system is not as well decoupled from Swing as the output system. For ease of use, the
 * methods are named the same as their corresponding Swing event listener methods, though they may
 * require additional arguments. These in turn invoke the {@link #generateBytes(ByteBuffer)} method,
 * which the implementor must send to the appropriate recipient, usually a pty.
 */
public abstract class TerminalAwtEventEncoder {
	public static final byte[] CODE_NONE = {};

	public static byte[] vtseq(int number) {
		try {
			return ("\033[" + number + "~").getBytes("ASCII");
		}
		catch (UnsupportedEncodingException e) {
			throw new AssertionError(e);
		}
	}

	public static final byte ESC = (byte) 0x1b;

	public static final byte[] CODE_INSERT = vtseq(2);
	public static final byte[] CODE_DELETE = vtseq(3);
	// Believe it or not, \r is ENTER on both Windows and Linux!
	public static final byte[] CODE_ENTER = { '\r' };
	public static final byte[] CODE_PAGE_UP = vtseq(5);
	public static final byte[] CODE_PAGE_DOWN = vtseq(6);
	public static final byte[] CODE_NUMPAD5 = { ESC, '[', 'E' };

	public static final byte[] CODE_UP_NORMAL = { ESC, '[', 'A' };
	public static final byte[] CODE_DOWN_NORMAL = { ESC, '[', 'B' };
	public static final byte[] CODE_RIGHT_NORMAL = { ESC, '[', 'C' };
	public static final byte[] CODE_LEFT_NORMAL = { ESC, '[', 'D' };
	public static final byte[] CODE_UP_APPLICATION = { ESC, 'O', 'A' };
	public static final byte[] CODE_DOWN_APPLICATION = { ESC, 'O', 'B' };
	public static final byte[] CODE_RIGHT_APPLICATION = { ESC, 'O', 'C' };
	public static final byte[] CODE_LEFT_APPLICATION = { ESC, 'O', 'D' };
	public static final byte[] CODE_HOME_NORMAL = { ESC, '[', 'H' };
	public static final byte[] CODE_END_NORMAL = { ESC, '[', 'F' };
	public static final byte[] CODE_HOME_APPLICATION = { ESC, 'O', 'H' };
	public static final byte[] CODE_END_APPLICATION = { ESC, 'O', 'F' };

	public static final byte[] CODE_F1 = { ESC, '[', '1', 'P' };
	public static final byte[] CODE_F2 = { ESC, '[', '1', 'Q' };
	public static final byte[] CODE_F3 = { ESC, '[', '1', 'R' };
	public static final byte[] CODE_F4 = { ESC, '[', '1', 'S' };
	public static final byte[] CODE_F5 = vtseq(15);
	public static final byte[] CODE_F6 = vtseq(17);
	public static final byte[] CODE_F7 = vtseq(18);
	public static final byte[] CODE_F8 = vtseq(19);
	public static final byte[] CODE_F9 = vtseq(20);
	public static final byte[] CODE_F10 = vtseq(21);
	public static final byte[] CODE_F11 = vtseq(23);
	public static final byte[] CODE_F12 = vtseq(24);
	public static final byte[] CODE_F13 = vtseq(25);
	public static final byte[] CODE_F14 = vtseq(26);
	public static final byte[] CODE_F15 = vtseq(28);
	public static final byte[] CODE_F16 = vtseq(29);
	public static final byte[] CODE_F17 = vtseq(31);
	public static final byte[] CODE_F18 = vtseq(32);
	public static final byte[] CODE_F19 = vtseq(33);
	public static final byte[] CODE_F20 = vtseq(34);

	public static final byte[] CODE_FOCUS_GAINED = { ESC, '[', 'I' };
	public static final byte[] CODE_FOCUS_LOST = { ESC, '[', 'O' };

	protected final Charset charset;
	protected final CharsetEncoder encoder;

	protected final ByteBuffer bb = ByteBuffer.allocate(16);
	protected final CharBuffer cb = CharBuffer.allocate(16);

	public TerminalAwtEventEncoder(String charsetName) {
		this(Charset.forName(charsetName));
	}

	public TerminalAwtEventEncoder(Charset charset) {
		this.charset = charset;
		this.encoder = charset.newEncoder();
	}

	protected abstract void generateBytes(ByteBuffer buf);

	protected byte[] getModifiedAnsiKeyCode(KeyEvent e) {
		int modifier = 1;
		if (e.isShiftDown()) {
			modifier += 1;
		}
		if (e.isAltDown()) {
			modifier += 2;
		}
		if (e.isControlDown()) {
			modifier += 4;
		}
		if (e.isMetaDown()) {
			modifier += 8;
		}
		int code = switch (e.getKeyCode()) {
			case KeyEvent.VK_HOME -> 1;
			case KeyEvent.VK_INSERT -> 2;
			case KeyEvent.VK_DELETE -> 3; // TODO: Already handled?
			case KeyEvent.VK_END -> 4;
			case KeyEvent.VK_PAGE_UP -> 5;
			case KeyEvent.VK_PAGE_DOWN -> 6;
			case KeyEvent.VK_F1 -> 11;
			case KeyEvent.VK_F2 -> 12;
			case KeyEvent.VK_F3 -> 13;
			case KeyEvent.VK_F4 -> 14;
			case KeyEvent.VK_F5 -> 15;
			case KeyEvent.VK_F6 -> 17;
			case KeyEvent.VK_F7 -> 18;
			case KeyEvent.VK_F8 -> 19;
			case KeyEvent.VK_F9 -> 20;
			case KeyEvent.VK_F10 -> 21;
			case KeyEvent.VK_F11 -> 23;
			case KeyEvent.VK_F12 -> 24;
			case KeyEvent.VK_F13 -> 25;
			case KeyEvent.VK_F14 -> 26;
			case KeyEvent.VK_F15 -> 28;
			case KeyEvent.VK_F16 -> 29;
			case KeyEvent.VK_F17 -> 31;
			case KeyEvent.VK_F18 -> 32;
			case KeyEvent.VK_F19 -> 33;
			case KeyEvent.VK_F20 -> 34;
			default -> -1;
		};
		if (code == -1) {
			return CODE_NONE;
		}
		try {
			// TODO: This doesn't seem to work right, but I'm lost trying to fix it.
			return "\033[%d;%d~".formatted(code, modifier).getBytes("ASCII");
		}
		catch (UnsupportedEncodingException ex) {
			throw new AssertionError(ex);
		}
	}

	protected byte[] getAnsiKeyCode(KeyEvent e, KeyMode cursorMode, KeyMode keypadMode) {
		if (e.getModifiersEx() != 0) {
			return getModifiedAnsiKeyCode(e);
		}
		return switch (e.getKeyCode()) {
			case KeyEvent.VK_INSERT -> CODE_INSERT;
			// NB. CODE_DELETE is handled in keyTyped
			// Yes, HOME and END are considered CURSOR keys
			case KeyEvent.VK_HOME -> cursorMode.choose(CODE_HOME_NORMAL, CODE_HOME_APPLICATION);
			case KeyEvent.VK_END -> cursorMode.choose(CODE_END_NORMAL, CODE_END_APPLICATION);
			case KeyEvent.VK_PAGE_UP -> CODE_PAGE_UP;
			case KeyEvent.VK_PAGE_DOWN -> CODE_PAGE_DOWN;
			case KeyEvent.VK_NUMPAD5 -> CODE_NUMPAD5;
			case KeyEvent.VK_UP -> cursorMode.choose(CODE_UP_NORMAL, CODE_UP_APPLICATION);
			case KeyEvent.VK_DOWN -> cursorMode.choose(CODE_DOWN_NORMAL, CODE_DOWN_APPLICATION);
			case KeyEvent.VK_RIGHT -> cursorMode.choose(CODE_RIGHT_NORMAL, CODE_RIGHT_APPLICATION);
			case KeyEvent.VK_LEFT -> cursorMode.choose(CODE_LEFT_NORMAL, CODE_LEFT_APPLICATION);
			case KeyEvent.VK_F1 -> CODE_F1;
			case KeyEvent.VK_F2 -> CODE_F2;
			case KeyEvent.VK_F3 -> CODE_F3;
			case KeyEvent.VK_F4 -> CODE_F4;
			case KeyEvent.VK_F5 -> CODE_F5;
			case KeyEvent.VK_F6 -> CODE_F6;
			case KeyEvent.VK_F7 -> CODE_F7;
			case KeyEvent.VK_F8 -> CODE_F8;
			case KeyEvent.VK_F9 -> CODE_F9;
			case KeyEvent.VK_F10 -> CODE_F10;
			case KeyEvent.VK_F11 -> CODE_F11;
			case KeyEvent.VK_F12 -> CODE_F12;
			case KeyEvent.VK_F13 -> CODE_F13;
			case KeyEvent.VK_F14 -> CODE_F14;
			case KeyEvent.VK_F15 -> CODE_F15;
			case KeyEvent.VK_F16 -> CODE_F16;
			case KeyEvent.VK_F17 -> CODE_F17;
			case KeyEvent.VK_F18 -> CODE_F18;
			case KeyEvent.VK_F19 -> CODE_F19;
			case KeyEvent.VK_F20 -> CODE_F20;
			// F21-F24 are not given on Wikipedia...
			default -> CODE_NONE;
		};
	}

	public void keyPressed(KeyEvent e, KeyMode cursorKeyMode, KeyMode keypadMode) {
		byte[] bytes = getAnsiKeyCode(e, cursorKeyMode, keypadMode);
		bb.put(bytes);
		generateBytesExc();
	}

	public void keyTyped(KeyEvent e) {
		sendChar(e.getKeyChar());
	}

	public void mousePressed(MouseEvent e, int row, int col) {
		mouseEvent(e, row, col, true);
	}

	public void mouseReleased(MouseEvent e, int row, int col) {
		mouseEvent(e, row, col, false);
	}

	protected int translateModifiers(InputEvent e) {
		int mods = 0;
		if (e.isShiftDown()) {
			mods += 4;
		}
		if (e.isMetaDown()) {
			mods += 8;
		}
		if (e.isControlDown()) {
			mods += 16;
		}
		return mods;
	}

	protected void sendMouseEvent(int buttonsAndModifiers, int row, int col) {
		cb.clear();
		cb.put("\033[M");
		cb.put((char) (' ' + buttonsAndModifiers));
		cb.put((char) (' ' + col));
		cb.put((char) (' ' + row));
		sendCharBuffer();
	}

	protected void mouseEvent(MouseEvent e, int row, int col, boolean isPress) {
		int buttonsAndModifiers = isPress ? switch (e.getButton()) {
			case MouseEvent.BUTTON1 -> 0;
			case MouseEvent.BUTTON2 -> 1;
			case MouseEvent.BUTTON3 -> 2;
			default -> throw new AssertionError();
		} : 3;
		buttonsAndModifiers += translateModifiers(e);
		sendMouseEvent(buttonsAndModifiers, row, col);
	}

	public void mouseWheelMoved(MouseWheelEvent e, int row, int col) {
		int buttonsAndModifiers = (e.getWheelRotation() < 0 ? 0 : 1) + 64;
		buttonsAndModifiers += translateModifiers(e);
		sendMouseEvent(buttonsAndModifiers, row, col);
	}

	public void focusGained() {
		bb.put(CODE_FOCUS_GAINED);
		generateBytesExc();
	}

	public void focusLost() {
		bb.put(CODE_FOCUS_LOST);
		generateBytesExc();
	}

	protected void sendCharBuffer() {
		cb.flip();
		CoderResult result = encoder.encode(cb, bb, true);
		cb.compact();
		if (result.isError()) {
			Msg.error(this, "Error while encoding");
			encoder.reset();
			cb.clear();
		}
		generateBytesExc();
	}

	public void sendChar(char c) {
		switch (c) {
			case 0x0a:
				bb.put(CODE_ENTER);
				generateBytesExc();
				break;
			case 0x7f:
				bb.put(CODE_DELETE);
				generateBytesExc();
				break;
			default:
				/**
				 * If I ever care to support Unicode, I may need to worry about surrogate pairs.
				 */
				cb.clear();
				cb.put(c);
				sendCharBuffer();
				break;
		}
	}

	protected void generateBytesExc() {
		bb.flip();
		try {
			if (bb.hasRemaining()) {
				generateBytes(bb);
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Error generating bytes: " + t, t);
		}
		finally {
			bb.clear();
		}
	}

	public void sendText(CharSequence text) {
		for (int i = 0; i < text.length(); i++) {
			sendChar(text.charAt(i));
		}
	}
}
