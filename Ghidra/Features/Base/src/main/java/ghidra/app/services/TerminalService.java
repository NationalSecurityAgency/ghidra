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
package ghidra.app.services;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;

import ghidra.app.plugin.core.terminal.TerminalPlugin;
import ghidra.app.plugin.core.terminal.vt.VtOutput;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * A service that provides for the creation and management of DEC VT100 terminal emulators.
 * 
 * <p>
 * These are perhaps better described as XTerm clones. It seems the term "VT100" is applied to any
 * text display that interprets some number of ANSI escape codes. While the XTerm documentation does
 * a decent job of listing which VT version (or Tektronix, or whatever terminal) that introduced or
 * specified each code/sequence in the last 6 or so decades, applications don't really seem to care
 * about the details. You set {@code TERM=xterm}, and they just use whatever codes the feel like.
 * Some make more conservative assumptions than others. For example, there is an escape sequence to
 * insert a blank character, shifting the remaining characters in the line to the right. Despite
 * using this, Bash (or perhaps Readline) will still re-send the remaining characters, just in case.
 * It seems over the years, in an effort to be compatible with as many applications as possible,
 * terminal emulators have implemented more and more escape codes, many of which were invented by
 * XTerm, and some of which result from mis-reading documentation and/or replicating erroneous
 * implementations.
 * 
 * <p>
 * Perhaps our interpretation of the history is jaded, and as we learn more, our implementation can
 * become more disciplined, but as it stands, our {@link TerminalPlugin} takes the <em>ad hoc</em>
 * approach: We've implemented the sequences we need to make it compatible with the applications we
 * intend to run, hoping that the resulting feature set will work with many others. It will likely
 * need patching to add missing features over its lifetime. We make extensive use of the
 * <a href="https://invisible-island.net/xterm/ctlseqs/ctlseqs.html">XTerm control sequence
 * documentation</a>, as well as the
 * <a href="https://en.wikipedia.org/wiki/ANSI_escape_code">Wikipedia article on ANSI escape
 * codes</a>. Where the documentation lacks specificity or otherwise seems incorrect, we experiment
 * with a reference implementation to discern and replicate its behavior. The clearest way we know
 * to do this is to run the {@code tty} command from the reference terminal to get its
 * pseudo-terminal (pty) file name. Then, we use Python from a separate terminal to write test
 * sequences to it and/or read sequences from it. We use the {@code sleep} command to prevent Bash
 * from reading its own terminal. This same process is applied to test our implementation.
 * 
 * <p>
 * The applications we've tested with include, without regard to version:
 * <ul>
 * <li>{@code bash}</li>
 * <li>{@code less}</li>
 * <li>{@code vim}</li>
 * <li>{@code gdb -tui}</li>
 * <li>{@code termmines} (from our Debugger training exercises)</li>
 * </ul>
 * 
 * <p>
 * Some known issues:
 * <ul>
 * <li>It seems Java does not provide all the key modifier information, esp., the meta key. Either
 * that or Ghidra's intercepting them. Thus, we can't encode those modifiers.</li>
 * <li>Many control sequences are not implemented. They're intentionally left to be implemented on
 * an as-needed basis.</li>
 * <li>We inherit many of the erroneous key encodings, e.g., for F1-F4, present in the reference
 * implementation.</li>
 * <li>Character sets are incomplete. The box/line drawing set is most important to us as it's used
 * by {@code gdb -tui}. Historically, these charsets are used to encode international characters.
 * Modern systems (and terminal emulators) support Unicode (though perhaps only UTF-8), but it's not
 * obvious how that interacts with the legacy charset switching. It's also likely many applications,
 * despite UTF-8 being available, will still use the legacy charset switching, esp., for box
 * drawing. Furthermore, because it's tedious work to figure the mapping for every character in a
 * charset, we've only cared to implement a portion of the box-drawing charset, and it's sorely
 * incomplete.</li>
 * </ul>
 */
@ServiceInfo(defaultProvider = TerminalPlugin.class)
public interface TerminalService {

	/**
	 * Create a terminal not connected to any particular application.
	 * 
	 * <p>
	 * To display application output, use {@link Terminal#injectDisplayOutput(java.nio.ByteBuffer)}.
	 * Application input is delivered to the given terminal output callback. If the application is
	 * connected via streams, esp., those from a pty, consider using
	 * {@link #createWithStreams(Charset, InputStream, OutputStream)}, instead.
	 * 
	 * @param charset the character set for the terminal. See note in
	 *            {@link #createWithStreams(Charset, InputStream, OutputStream)}.
	 * @param outputCb callback for output from the terminal, i.e., the application's input.
	 * @return the terminal
	 */
	Terminal createNullTerminal(Charset charset, VtOutput outputCb);

	/**
	 * Create a terminal connected to the application (or pty session) via the given streams.
	 * 
	 * @param charset the character set for the terminal. <b>NOTE:</b> Only US-ASCII and UTF-8 have
	 *            been tested. So long as the bytes 0x00-0x7f map one-to-one with characters with
	 *            the same code point, it'll probably work. Charsets that require more than one byte
	 *            to decode those characters will almost certainly break things.
	 * @param in the application's output, i.e., input for the terminal to display.
	 * @param out the application's input, i.e., output from the terminal's keyboard and mouse.
	 * @return the terminal
	 */
	Terminal createWithStreams(Charset charset, InputStream in, OutputStream out);

	/**
	 * Remove all terminals whose sessions have terminated from the tool
	 * 
	 * <p>
	 * This is done automatically when creating any new terminal.
	 */
	void cleanTerminated();
}
