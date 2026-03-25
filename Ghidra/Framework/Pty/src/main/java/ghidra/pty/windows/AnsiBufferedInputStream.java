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
package ghidra.pty.windows;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.stream.Stream;

// TODO: I shouldn't have to do any of this.
public class AnsiBufferedInputStream extends InputStream {
	private static final Charset WINDOWS_1252 = Charset.forName("windows-1252");

	private enum Mode {
		CHARS,
		ESC,
		CSI,
		CSI_p,
		CSI_Q,
		OSC,
		WINDOW_TITLE,
		WINDOW_TITLE_ESC;
	}

	private final InputStream in;

	private int countIn = 0;

	private ByteBuffer lineBaked = ByteBuffer.allocate(Short.MAX_VALUE);
	private ByteBuffer lineBuf = ByteBuffer.allocate(Short.MAX_VALUE);
	private ByteBuffer escBuf = ByteBuffer.allocate(1024);
	private ByteBuffer titleBuf = ByteBuffer.allocate(255);

	private Mode mode = Mode.CHARS;

	public AnsiBufferedInputStream(InputStream in) {
		if (in instanceof HandleInputStream) {
			// Spare myself the 1-by-1 native calls
			in = new BufferedInputStream(in);
		}
		this.in = in;

		lineBuf.limit(0);
		lineBaked.limit(0);
	}

	@Override
	public int read() throws IOException {
		if (lineBaked.hasRemaining()) {
			return lineBaked.get();
		}
		if (readUntilBaked() < 0) {
			return -1;
		}
		if (lineBaked.hasRemaining()) {
			return lineBaked.get();
		}
		return -1; // EOF
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (!lineBaked.hasRemaining()) {
			if (readUntilBaked() < 0) {
				return -1;
			}
		}
		int read = Math.min(lineBaked.remaining(), len);
		lineBaked.get(b, off, read);
		return read;
	}

	@Override
	public void close() throws IOException {
		in.close();
		super.close();
	}

	protected int readUntilBaked() throws IOException {
		while (!lineBaked.hasRemaining()) {
			if (processNext() < 0) {
				break;
			}
		}
		if (!lineBaked.hasRemaining()) {
			return -1;
		}
		return lineBaked.remaining();
	}

	protected void printDebugChar(byte c) {
		if (0x20 <= c && c <= 0x7f) {
			System.err.print(new String(new byte[] { c }));
		}
		else {
			System.err.print(String.format("<%02x>", c & 0xff));
		}
	}

	protected int processNext() throws IOException {
		int ci = in.read();
		if (ci == -1) {
			return -1;
		}
		byte c = (byte) ci;
//		printDebugChar(c);
		switch (mode) {
			case CHARS -> processChars(c);
			case ESC -> processEsc(c);
			case CSI -> processCsi(c);
			case CSI_p -> processCsiParamOrCommand(c);
			case CSI_Q -> processCsiQ(c);
			case OSC -> processOsc(c);
			case WINDOW_TITLE -> processWindowTitle(c);
			case WINDOW_TITLE_ESC -> processWindowTitleEsc(c);
			default -> throw new AssertionError();
		}
		countIn++;
		return c;
	}

	/**
	 * There's not really a good way to know if any trailing space was intentional. For GDB/MI, that
	 * doesn't really matter.
	 */
	protected int guessEnd() {
		for (int i = lineBuf.limit() - 1; i >= 0; i--) {
			byte c = lineBuf.get(i);
			if (c != 0x20 && c != 0) {
				return i + 1;
			}
		}
		return 0;
	}

	protected void bakeLine() {
		lineBuf.position(0);
		lineBuf.limit(guessEnd() + 1);
		lineBuf.put(lineBuf.limit() - 1, (byte) '\n');
		ByteBuffer temp = lineBaked;
		lineBaked = lineBuf;
		lineBuf = temp;
		lineBuf.clear();
		Arrays.fill(lineBuf.array(), (byte) 0);
		lineBuf.limit(0);
	}

	protected void appendChar(byte c) {
		int limit = lineBuf.limit();
		if (lineBuf.position() == limit) {
			lineBuf.limit(limit + 1);
		}
		lineBuf.put(c);
	}

	protected void processChars(byte c) {
		switch (c) {
			default -> appendChar(c);
			case '\b' -> {
				if (lineBuf.get(lineBuf.position() - 1) == ' ') {
					lineBuf.position(lineBuf.position() - 1);
				}
			}
			case '\n' -> bakeLine();
			case '\r' -> lineBuf.position(0);
			case 0x1b -> mode = Mode.ESC;
		}
	}

	protected void processEsc(byte c) {
		switch (c) {
			case '[' -> mode = Mode.CSI;
			case ']' -> mode = Mode.OSC;
			default -> throw new AssertionError("Saw 'ESC " + c + "' at " + countIn);
		}
	}

	protected void processCsi(byte c) {
		switch (c) {
			default -> processCsiParamOrCommand(c);
			case '?' -> mode = Mode.CSI_Q;
		}
	}

	protected void processCsiParamOrCommand(byte c) {
		switch (c) {
			default -> escBuf.put(c);
			case 'A' -> {
				execCursorUp();
				mode = Mode.CHARS;
			}
			case 'B' -> {
				execCursorDown();
				mode = Mode.CHARS;
			}
			case 'C' -> {
				execCursorForward();
				mode = Mode.CHARS;
			}
			case 'D' -> {
				execCursorBackward();
				mode = Mode.CHARS;
			}
			case 'G' -> {
				execCursorCharAbsolute();
				mode = Mode.CHARS;
			}
			case 'H' -> {
				execCursorPosition();
				mode = Mode.CHARS;
			}
			case 'J' -> {
				execEraseInDisplay();
				mode = Mode.CHARS;
			}
			case 'K' -> {
				execEraseInLine();
				mode = Mode.CHARS;
			}
			case 'X' -> {
				execEraseCharacter();
				mode = Mode.CHARS;
			}
			case 'm' -> {
				execSetGraphicsRendition();
				mode = Mode.CHARS;
			}
			case 'h' -> {
				execPrivateSequence(true);
				mode = Mode.CHARS;
			}
			case 'l' -> {
				execPrivateSequence(false);
				mode = Mode.CHARS;
			}
		}
	}

	public static final String PRIV_12 = "12";
	public static final String PRIV_25 = "25";
	public static final String PRIV_1004 = "1004";
	public static final String PRIV_2004 = "2004";
	public static final String PRIV_9001 = "9001";

	protected void processCsiQ(byte c) {
		switch (c) {
			default -> escBuf.put(c);
			case 'h' -> {
				switch (readAndClearEscBuf()) {
					case PRIV_12 -> execTextCursorEnableBlinking();
					case PRIV_25 -> execTextCursorEnableModeShow();
					case PRIV_1004 -> execEnableFocusReport();
					case PRIV_2004 -> execEnableBracketedPasteMode();
					case PRIV_9001 -> execEnableWin32InputMode();
					case String buf -> throw new AssertionError("Got CsiQ(h): %s".formatted(buf));
				}
				mode = Mode.CHARS;
			}
			case 'l' -> {
				switch (readAndClearEscBuf()) {
					case PRIV_12 -> execTextCursorDisableBlinking();
					case PRIV_25 -> execTextCursorDisableModeShow();
					case PRIV_1004 -> execDisableFocusReport();
					case PRIV_2004 -> execDisableBracketedPasteMode();
					case PRIV_9001 -> execDisableWin32InputMode();
					case String buf -> throw new AssertionError("Got CsiQ(l): %s".formatted(buf));
				}
				mode = Mode.CHARS;
			}
		}
	}

	protected void processOsc(byte c) {
		switch (c) {
			default -> escBuf.put(c);
			case ';' -> {
				switch (readAndClearEscBuf()) {
					case "0", "2" -> mode = Mode.WINDOW_TITLE;
					default -> throw new AssertionError();
				}
			}
		}
	}

	protected void processWindowTitle(byte c) {
		switch (c) {
			default -> titleBuf.put(c);
			case 0x07 -> { // bell, even though MSDN says longer form preferred
				execSetWindowTitle();
				mode = Mode.CHARS;
			}
			case 0x1b -> mode = Mode.WINDOW_TITLE_ESC;
		}
	}

	protected void processWindowTitleEsc(byte c) {
		switch (c) {
			case '\\' -> {
				execSetWindowTitle();
				mode = Mode.CHARS;
			}
			default -> throw new AssertionError("Saw <ST> ... ESC " + c + " at " + countIn);
		}
	}

	protected String readAndClear(ByteBuffer buf) {
		buf.flip();
		String result = new String(buf.array(), buf.position(), buf.remaining(), WINDOWS_1252);
		buf.clear();
		return result;
	}

	protected String readAndClearEscBuf() {
		return readAndClear(escBuf);
	}

	protected int parseNumericBuffer() {
		String numeric = readAndClearEscBuf();
		if (numeric.isEmpty()) {
			return 0;
		}
		int result = Integer.parseInt(numeric);
		return result;
	}

	protected int[] parseNumericListBuffer() {
		String numericList = readAndClearEscBuf();
		if (numericList.isEmpty()) {
			return new int[] {};
		}
		return Stream.of(numericList.split(";"))
				.mapToInt(Integer::parseInt)
				.toArray();
	}

	protected void execCursorUp() {
		throw new UnsupportedOperationException("Cursor Up");
	}

	protected void execCursorDown() {
		throw new UnsupportedOperationException("Cursor Down");
	}

	protected void setPosition(int newPosition) {
		if (lineBuf.limit() < newPosition) {
			lineBuf.limit(newPosition);
		}
		lineBuf.position(newPosition);
	}

	protected void execCursorForward() {
		int delta = parseNumericBuffer();
		setPosition(lineBuf.position() + delta);
	}

	protected void execCursorBackward() {
		int delta = parseNumericBuffer();
		lineBuf.position(lineBuf.position() - delta);
	}

	protected void execCursorCharAbsolute() {
		int abs = parseNumericBuffer();
		lineBuf.position(abs - 1);
	}

	protected void execCursorPosition() {
		int[] yx = parseNumericListBuffer();
		if (yx.length == 0) {
			lineBuf.position(0);
			return;
		}
		if (yx.length != 2) {
			throw new AssertionError();
		}
		if (yx[0] != 1) {
			throw new AssertionError();
		}
		lineBuf.position(yx[1] - 1);
	}

	protected void execTextCursorEnableBlinking() {
		// Don't care
	}

	protected void execTextCursorDisableBlinking() {
		// Don't care
	}

	protected void execTextCursorEnableModeShow() {
		// Don't care
	}

	protected void execTextCursorDisableModeShow() {
		// Don't care
	}

	protected void execEnableFocusReport() {
		// Don't care
	}

	protected void execDisableFocusReport() {
		// Don't care
	}

	protected void execEnableBracketedPasteMode() {
		// Don't care
	}

	protected void execDisableBracketedPasteMode() {
		// Don't care
	}

	protected void execEnableWin32InputMode() {
		// Don't care
	}

	protected void execDisableWin32InputMode() {
		// Don't care
	}

	protected void execEraseInDisplay() {
		// Because I have only one line, right?
		execEraseInLine();
	}

	protected void execEraseInLine() {
		switch (parseNumericBuffer()) {
			case 0 -> Arrays.fill(lineBuf.array(), lineBuf.position(), lineBuf.capacity(),
				(byte) 0);
			case 1 -> Arrays.fill(lineBuf.array(), 0, lineBuf.position() + 1, (byte) 0);
			case 2 -> Arrays.fill(lineBuf.array(), (byte) 0);
		}
	}

	protected void execEraseCharacter() {
		int count = parseNumericBuffer();
		Arrays.fill(lineBuf.array(), lineBuf.position(), lineBuf.position() + count, (byte) ' ');
	}

	protected void execSetGraphicsRendition() {
		// TODO: Maybe echo these or provide callbacks
		// Otherwise, don't care
		escBuf.clear();
	}

	protected void execSetWindowTitle() {
		// Msg.info(this, "Title: " + readAndClear(titleBuf));
		// TODO: Maybe a callback. Otherwise, don't care
		titleBuf.clear();
	}

	protected void execPrivateSequence(boolean enable) {
		// These don't matter for input buffering.
		escBuf.clear();
	}
}
