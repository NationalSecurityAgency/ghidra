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

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

import ghidra.app.services.TerminalService;
import ghidra.util.Msg;

/**
 * A terminal with a background thread and input stream powering its display.
 * 
 * <p>
 * The thread eagerly reads the given input stream and pumps it into the given provider. Be careful
 * using {@link #injectDisplayOutput(ByteBuffer)}. While it is synchronized, there's no guarantee
 * escape codes don't get mixed up. Note that this does not make any effort to connect the
 * terminal's keyboard to any output stream.
 * 
 * @see TerminalService#createWithStreams(java.nio.charset.Charset, InputStream, OutputStream)
 */
public class ThreadedTerminal extends DefaultTerminal {

	protected final ReadableByteChannel in;
	protected final Thread pumpThread = new Thread(this::pump);
	protected final ByteBuffer buffer = ByteBuffer.allocate(1024);

	protected boolean closed = false;

	/**
	 * Construct a terminal connected to the given input stream
	 * 
	 * @param provider the provider
	 * @param in the input stream
	 */
	public ThreadedTerminal(TerminalProvider provider, InputStream in) {
		super(provider);
		this.in = Channels.newChannel(in);
		this.pumpThread.start();
	}

	@Override
	public void close() {
		closed = true;
		pumpThread.interrupt();
		super.close();
	}

	static void printBuffer(String prefix, ByteBuffer bb) {
		byte[] bytes = new byte[bb.remaining()];
		bb.get(bb.position(), bytes);
		System.err.print(prefix);
		try {
			String str = new String(bytes, "US-ASCII");
			for (char c : str.toCharArray()) {
				if (c == 0x1b) {
					System.err.print("\n\\x1b");
				}
				else if (c < ' ' || c > '\u007f') {
					System.err.print("\\x%02x".formatted((int) c));
				}
				else {
					System.err.print(c);
				}
			}
			System.err.println();
		}
		catch (UnsupportedEncodingException e) {
			System.err.println("Couldn't decode");
		}
	}

	protected void pump() {
		try {
			while (!closed) {
				if (-1 == in.read(buffer) || closed) {
					return;
				}
				buffer.flip();
				//printBuffer("<< ", buffer);
				synchronized (buffer) {
					provider.processInput(buffer);
				}
				buffer.clear();
			}
		}
		catch (IOException e) {
			Msg.error(this, "Console input closed unexpectedly: " + e);
			closed = true;
		}
	}

	@Override
	public void injectDisplayOutput(ByteBuffer bb) {
		synchronized (buffer) {
			provider.processInput(bb);
		}
	}
}
