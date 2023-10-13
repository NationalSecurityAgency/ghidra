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

import java.nio.ByteBuffer;

/**
 * The parser for a terminal emulator
 * 
 * <p>
 * The only real concern of this parser is to separate escape sequences from normal character
 * output. All state not related to parsing is handled by a {@link VtHandler}. Most of the logic is
 * implemented in the machine state nodes: {@link VtState}.
 */
public class VtParser {
	protected final VtHandler handler;
	protected VtState state = VtState.CHAR;

	protected VtCharset.G csG;
	protected ByteBuffer csiParam = ByteBuffer.allocate(100);
	protected ByteBuffer csiInter = ByteBuffer.allocate(100);
	protected ByteBuffer oscParam = ByteBuffer.allocate(100);

	/**
	 * Construct a parser with the given handler
	 * 
	 * @param handler the handler
	 */
	public VtParser(VtHandler handler) {
		this.handler = handler;
	}

	/**
	 * Create a copy of the CSI buffers, reconstructed as they were in the original stream.
	 * 
	 * <p>
	 * This is used to re-process parsed bytes after broken CSI sequence
	 * 
	 * @param b the character currently being parsed
	 * @return the copy
	 */
	protected ByteBuffer copyCsiBuffer(byte b) {
		csiParam.flip();
		csiInter.flip();
		ByteBuffer buf = ByteBuffer.allocate(2 + csiParam.remaining() + csiInter.remaining());
		buf.put((byte) '[');
		buf.put(csiParam);
		buf.put(csiInter);
		buf.put(b);
		csiParam.clear();
		csiInter.clear();
		return buf;
	}

	/**
	 * Create a copy of the OSC buffers, reconstructed as they were in the original stream.
	 * 
	 * <p>
	 * This is used to re-process parsed bytes after a broken OSC sequence
	 * 
	 * @param b the character currently being parsed
	 * @return the copy
	 */
	protected ByteBuffer copyOscBuffer(byte b) {
		oscParam.flip();
		ByteBuffer buf = ByteBuffer.allocate(2 + oscParam.remaining());
		buf.put((byte) ']');
		buf.put(oscParam);
		buf.put(b);
		oscParam.clear();
		return buf;
	}

	/**
	 * Process the bytes from the given buffer
	 * 
	 * <p>
	 * This is likely fed from an input stream, usually of a pty.
	 * 
	 * @param buf the buffer
	 */
	public void process(ByteBuffer buf) {
		state = doProcess(state, buf);
	}

	/**
	 * Process a given byte by delegating to the current state machine node
	 * 
	 * @param state the node
	 * @param b the byte
	 * @return the new state node
	 */
	protected VtState doProcessByte(VtState state, byte b) {
		return state.handleNext(b, this, handler);
	}

	/**
	 * Process a given byte buffer, one byte at a time
	 * 
	 * @param state the initial machine state node
	 * @param buf the buffer
	 * @return the resulting machine state node
	 */
	protected VtState doProcess(VtState state, ByteBuffer buf) {
		while (buf.hasRemaining()) {
			state = doProcessByte(state, buf.get());
		}
		return state;
	}
}
