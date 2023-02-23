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
package agent.gdb.pty.windows;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Set;
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
		// printDebugChar(c);
		switch (mode) {
			case CHARS:
				processChars(c);
				break;
			case ESC:
				processEsc(c);
				break;
			case CSI:
				processCsi(c);
				break;
			case CSI_p:
				processCsiParamOrCommand(c);
				break;
			case CSI_Q:
				processCsiQ(c);
				break;
			case OSC:
				processOsc(c);
				break;
			case WINDOW_TITLE:
				processWindowTitle(c);
				break;
			case WINDOW_TITLE_ESC:
				processWindowTitleEsc(c);
				break;
			default:
				throw new AssertionError();
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
			case 0x08:
				if (lineBuf.get(lineBuf.position() - 1) == ' ') {
					lineBuf.position(lineBuf.position() - 1);
				}
				break;
			case '\n':
				//appendChar(c);
				bakeLine();
				break;
			case 0x1b:
				mode = Mode.ESC;
				break;
			default:
				appendChar(c);
				break;
		}
	}

	protected void processEsc(byte c) {
		switch (c) {
			case '[':
				mode = Mode.CSI;
				break;
			case ']':
				mode = Mode.OSC;
				break;
			default:
				throw new AssertionError("Saw 'ESC " + c + "' at " + countIn);
		}
	}

	protected void processCsi(byte c) {
		switch (c) {
			default:
				processCsiParamOrCommand(c);
				break;
			case '?':
				mode = Mode.CSI_Q;
				break;
		}
	}

	protected void processCsiParamOrCommand(byte c) {
		switch (c) {
			default:
				escBuf.put(c);
				break;
			case 'A':
				execCursorUp();
				mode = Mode.CHARS;
				break;
			case 'B':
				execCursorDown();
				mode = Mode.CHARS;
				break;
			case 'C':
				execCursorForward();
				mode = Mode.CHARS;
				break;
			case 'D':
				execCursorBackward();
				mode = Mode.CHARS;
				break;
			case 'H':
				execCursorPosition();
				mode = Mode.CHARS;
				break;
			case 'J':
				execEraseInDisplay();
				mode = Mode.CHARS;
				break;
			case 'K':
				execEraseInLine();
				mode = Mode.CHARS;
				break;
			case 'X':
				execEraseCharacter();
				mode = Mode.CHARS;
				break;
			case 'm':
				execSetGraphicsRendition();
				mode = Mode.CHARS;
				break;
		}
	}

	protected void processCsiQ(byte c) {
		String buf;
		switch (c) {
			default:
				escBuf.put(c);
				break;
			case 'h':
				buf = readAndClearEscBuf();
				if ("12".equals(buf)) {
					execTextCursorEnableBlinking();
					escBuf.clear();
					mode = Mode.CHARS;
				}
				else if ("25".equals(buf)) {
					execTextCursorEnableModeShow();
					escBuf.clear();
					mode = Mode.CHARS;
				}
				else {
					throw new AssertionError();
				}
				break;
			case 'l':
				buf = readAndClearEscBuf();
				if ("12".equals(buf)) {
					execTextCursorDisableBlinking();
					escBuf.clear();
					mode = Mode.CHARS;
				}
				else if ("25".equals(buf)) {
					execTextCursorDisableModeShow();
					escBuf.clear();
					mode = Mode.CHARS;
				}
				break;
		}
	}

	protected void processOsc(byte c) {
		switch (c) {
			default:
				escBuf.put(c);
				break;
			case ';':
				if (Set.of("0", "2").contains(readAndClearEscBuf())) {
					mode = Mode.WINDOW_TITLE;
					escBuf.clear();
					break;
				}
				throw new AssertionError();
		}
	}

	protected void processWindowTitle(byte c) {
		switch (c) {
			default:
				titleBuf.put(c);
				break;
			case 0x07: // bell, even though MSDN says longer form preferred
				execSetWindowTitle();
				mode = Mode.CHARS;
				break;
			case 0x1b:
				mode = Mode.WINDOW_TITLE_ESC;
				break;
		}
	}

	protected void processWindowTitleEsc(byte c) {
		switch (c) {
			case '\\':
				execSetWindowTitle();
				mode = Mode.CHARS;
				break;
			default:
				throw new AssertionError("Saw <ST> ... ESC " + c + " at " + countIn);
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

	protected void execEraseInDisplay() {
		// Because I have only one line, right?
		execEraseInLine();
	}

	protected void execEraseInLine() {
		switch (parseNumericBuffer()) {
			case 0:
				Arrays.fill(lineBuf.array(), lineBuf.position(), lineBuf.capacity(), (byte) 0);
				break;
			case 1:
				Arrays.fill(lineBuf.array(), 0, lineBuf.position() + 1, (byte) 0);
				break;
			case 2:
				Arrays.fill(lineBuf.array(), (byte) 0);
				break;
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
}
