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
package ghidra.app.plugin.core.interpreter;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.text.BadLocationException;

/**
 * A text stream processor that invokes callbacks for ANSI escape codes.
 *
 * <p>
 * The general pattern is: 1) Implement {@link AnsiParserHandler}, 2) Construct a parser, passing in
 * your handler, 3) Invoke {@link #processString(String)} as needed. The parser keeps an internal
 * buffer so that input text can be streamed incrementally.
 */
class AnsiParser {
	/**
	 * A 7-bit CSI sequence consists of ESC [, followed by any number of parameter characters in the
	 * range 0x30-0x3f, followed by any number of intermediate characters in the range 0x20-0x2f,
	 * followed by a single final character in the range 0x40-0x7e.
	 */
	private static final String CSI_PARAM_EXPR = "[\\x30-\\x3F]*";
	private static final String CSI_INTER_EXPR = "[\\x20-\\x2F]*";
	private static final String CSI_FINAL_EXPR = "[\\x40-\\x7E]";
	/** A regex to match a complete CSI sequence and parse the pieces as groups */
	private static final String CSI_MATCH_EXPR = String.format(
		"\\x1b\\[(?<CSIPARAM>%s)(?<CSIINTER>%s)(?<CSIFINAL>%s)",
		CSI_PARAM_EXPR,
		CSI_INTER_EXPR,
		CSI_FINAL_EXPR);
	/** A regex to match an unfinished CSI sequence at the end of the input */
	private static final String CSI_TAIL_EXPR = String.format(
		"\\x1b(?:\\[(?:%s(?:%s)?)?)?\\z",
		CSI_PARAM_EXPR,
		CSI_INTER_EXPR);

	/**
	 * A 7-bit OSC sequence consists of ESC ], followed by any number of non-control parameter
	 * characters, followed by a BEL character \x07 or the ST sequence ESC \
	 */
	private static final String OSC_PARAM_EXPR = "[\\x20-\\x7F]*";
	/** A regex to match a complete OSC sequence and extract the parameter as a group */
	private static final String OSC_MATCH_EXPR = String.format(
		"\\x1b\\](?<OSCPARAM>%s)(?:\\x07|\\x1b\\\\)",
		OSC_PARAM_EXPR);
	/** A regex to match an unfinished OSC sequence at the end of the input */
	private static final String OSC_TAIL_EXPR = String.format(
		"\\x1b(?:\\](?:%s(?:\\x1b)?)?)?\\z",
		OSC_PARAM_EXPR);

	/** A combined regex to match a complete control sequence */
	private static final Pattern CTRL_SEQ = Pattern.compile(String.format(
		"(?<CSI>%s)|(?<OSC>%s)|(?<NUL>\\x00)",
		CSI_MATCH_EXPR,
		OSC_MATCH_EXPR));

	/** A combined regex to match an unfinished control sequence */
	private static final Pattern CTRL_TAIL = Pattern.compile(String.format(
		"%s|%s",
		CSI_TAIL_EXPR,
		OSC_TAIL_EXPR));

	/**
	 * The interface for parser callbacks.
	 * 
	 * <p>
	 * See <a href="https://en.wikipedia.org/wiki/ANSI_escape_code">ANSI escape code</a> on
	 * Wikipedia.
	 */
	interface AnsiParserHandler {
		/**
		 * Callback for a portion of text
		 * 
		 * @param text the text
		 * @throws BadLocationException if there was an issue rendering the text into a document
		 */
		default void handleString(String text) throws BadLocationException {
		}

		/**
		 * Callback for an ANSI Control Sequence Introducer sequence
		 * 
		 * @param param zero or more parameter bytes ({@code 0-9:;<=>?})
		 * @param inter zero or more intermediate bytes (space {@code!"#$%&'()*+,-./}
		 * @param finalChar the final byte ({@code @A-Z[\]^_`a-z{|}~})
		 * @throws BadLocationException if there was an issue applying the sequence to a document
		 */
		default void handleCSI(String param, String inter, String finalChar)
				throws BadLocationException {
		}

		/**
		 * Callback for an ANSI Operating System Command sequence
		 * 
		 * @param param zero or more parameter bytes in the ASCII printable range
		 * @throws BadLocationException if there was an issue applying the sequence to a document
		 */
		default void handleOSC(String param) throws BadLocationException {
		}
	}

	private final StringBuffer sb = new StringBuffer();
	private final AnsiParserHandler handler;

	/**
	 * Construct a parser with the given handler
	 * 
	 * @param handler the callbacks to invoke during parsing
	 */
	public AnsiParser(AnsiParserHandler handler) {
		this.handler = handler;
	}

	/**
	 * Process a portion of input text
	 * 
	 * @param text the portion to process
	 * @throws BadLocationException if there was an issue rendering the portion into a document
	 */
	public void processString(String text) throws BadLocationException {
		sb.append(text);
		Matcher m = CTRL_SEQ.matcher(sb);
		int lastPos = 0;
		while (m.find()) {
			if (m.start() > lastPos) {
				handler.handleString(sb.substring(lastPos, m.start()));
			}

			if (m.group("CSI") != null) {
				handler.handleCSI(m.group("CSIPARAM"), m.group("CSIINTER"), m.group("CSIFINAL"));
			}
			else if (m.group("OSC") != null) {
				handler.handleOSC(m.group("OSCPARAM"));
			}
			else if (m.group("NUL") != null) {
				// Suppress NUL bytes from the output.
				// TTY commands, such as "clear", that see TERM=vt100
				// may append NUL padding to their output, which a real vt100 would need.
			}
			lastPos = m.end();
		}

		m = CTRL_TAIL.matcher(sb);
		if (m.find(lastPos)) {
			if (lastPos < m.start()) {
				handler.handleString(sb.substring(lastPos, m.start()));
			}
			sb.delete(0, m.start());
		}
		else {
			if (lastPos < sb.length()) {
				handler.handleString(sb.substring(lastPos));
			}
			sb.setLength(0);
		}
	}
}
