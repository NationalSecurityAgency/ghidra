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
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.terminal.vt.VtOutput;
import ghidra.app.services.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * The plugin that provides {@link TerminalService}
 */
@PluginInfo(
	status = PluginStatus.STABLE,
	category = PluginCategoryNames.COMMON,
	packageName = CorePluginPackage.NAME,
	description = "Provides VT100 Terminal Emulation",
	shortDescription = "VT100 Emulator",
	servicesProvided = { TerminalService.class })
public class TerminalPlugin extends Plugin implements TerminalService {

	protected ClipboardService clipboardService;

	protected List<TerminalProvider> providers = new ArrayList<>();

	public TerminalPlugin(PluginTool tool) {
		super(tool);
		clipboardService = tool.getService(ClipboardService.class);
	}

	@Override
	public void cleanTerminated() {
		Swing.runIfSwingOrRunLater(this::doCleanTerminated);
	}

	protected void doCleanTerminated() {
		for (TerminalProvider provider : List.copyOf(providers)) {
			if (provider.isTerminated()) {
				provider.removeFromTool();
			}
		}
	}

	public TerminalProvider createProvider(Plugin helpPlugin, Charset charset, VtOutput outputCb) {
		return Swing.runNow(() -> {
			cleanTerminated();
			TerminalProvider provider = new TerminalProvider(this, charset, helpPlugin);
			provider.setOutputCallback(outputCb);
			provider.addToTool();
			provider.setVisible(true);
			providers.add(provider);
			provider.setClipboardService(clipboardService);
			provider.toFront();
			return provider;
		});
	}

	@Override
	public Terminal createNullTerminal(Plugin helpPlugin, Charset charset, VtOutput outputCb) {
		return new DefaultTerminal(createProvider(helpPlugin, charset, outputCb));
	}

	@Override
	public Terminal createNullTerminal(Charset charset, VtOutput outputCb) {
		return createNullTerminal(this, charset, outputCb);
	}

	@Override
	public Terminal createWithStreams(Plugin helpPlugin, Charset charset, InputStream in,
			OutputStream out) {
		WritableByteChannel channel = Channels.newChannel(out);
		return new ThreadedTerminal(createProvider(helpPlugin, charset, buf -> {
			while (buf.hasRemaining()) {
				try {
					//ThreadedTerminal.printBuffer(">> ", buf);
					channel.write(buf);
				}
				catch (IOException e) {
					Msg.error(this, "Could not write terminal output: " + e);
				}
			}
		}), in);
	}

	@Override
	public Terminal createWithStreams(Charset charset, InputStream in, OutputStream out) {
		return createWithStreams(this, charset, in, out);
	}

	static class TerminalOutputStream extends OutputStream {
		private final TerminalProvider terminal;

		public TerminalOutputStream(TerminalProvider terminal) {
			this.terminal = terminal;
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			terminal.processInput(ByteBuffer.wrap(b, off, len));
		}

		@Override
		public void write(byte[] b) throws IOException {
			terminal.processInput(ByteBuffer.wrap(b));
		}

		@Override
		public void write(int b) throws IOException {
			write(new byte[] { (byte) b });
		}
	}

	static class TerminalInputStream extends InputStream implements VtOutput, TerminalListener {
		private static final int SLACK = 4096;

		private final Object lock = new Object();
		private final TerminalProvider terminal;

		private ByteBuffer buf = ByteBuffer.allocate(SLACK);

		public TerminalInputStream(TerminalProvider terminal) {
			this.terminal = terminal;
			terminal.setOutputCallback(this);
			terminal.addTerminalListener(this);
		}

		@Override
		public void terminated(int exitcode) {
			synchronized (lock) {
				lock.notifyAll();
			}
		}

		@Override
		public void out(ByteBuffer buf) {
			synchronized (lock) {
				while (true) {
					try {
						this.buf.put(buf);
						lock.notify();
						break;
					}
					catch (BufferOverflowException e) {
						ByteBuffer old = this.buf;
						this.buf = ByteBuffer.allocate(old.capacity() + buf.remaining() + SLACK);
						old.flip();
						this.buf.put(old);
					}
				}
			}
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			if (len < 0) {
				throw new IllegalArgumentException("len < 0");
			}
			if (len == 0) {
				return 0;
			}
			synchronized (lock) {
				while (this.buf.position() == 0) {
					if (terminal.isTerminated()) {
						return -1;
					}
					try {
						lock.wait();
					}
					catch (InterruptedException e) {
						// repeat
					}
				}
				this.buf.flip();
				int res = Math.min(len, this.buf.remaining());
				this.buf.get(b, off, res);
				this.buf.compact();
				return res;
			}
		}

		@Override
		public int read(byte[] b) throws IOException {
			return read(b, 0, b.length);
		}

		@Override
		public int read() throws IOException {
			byte[] b = new byte[1];
			if (read(b) == -1) {
				return -1;
			}
			return Byte.toUnsignedInt(b[0]);
		}
	}

	@Override
	public TerminalGivingStreams createGivingStreams(Plugin helpPlugin, Charset charset) {
		TerminalProvider provider = createProvider(helpPlugin, charset, null);
		TerminalInputStream in = new TerminalInputStream(provider);
		TerminalOutputStream out = new TerminalOutputStream(provider);
		return new TerminalGivingStreams(new DefaultTerminal(provider), in, out);
	}

	@Override
	public TerminalGivingStreams createGivingStreams(Charset charset) {
		return createGivingStreams(this, charset);
	}

	@Override
	public void serviceAdded(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ClipboardService.class) {
			clipboardService = (ClipboardService) service;
			for (TerminalProvider p : providers) {
				p.setClipboardService(clipboardService);
			}
		}
	}

	@Override
	public void serviceRemoved(Class<?> interfaceClass, Object service) {
		if (interfaceClass == ClipboardService.class) {
			for (TerminalProvider p : providers) {
				p.setClipboardService(null);
			}
		}
	}
}
