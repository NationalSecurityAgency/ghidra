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

import java.awt.Color;

import javax.swing.text.*;

import generic.theme.GColor;
import ghidra.app.plugin.core.interpreter.AnsiParser.AnsiParserHandler;
import ghidra.util.ColorUtils;

/**
 * An object for parsing and rendering ANSI-styled strings into a Swing {@link Document}.
 * 
 * <p>
 * Depending on the use case, it may be appropriate to instantiate multiple parsers, even if they
 * are inserting contents into the same document, e.g., to process a terminal's stdout and stderr
 * independently. Keep in mind, despite using separate renderers, escape codes emitted on stderr
 * will still affect any following text emitted on stdout and vice versa. However, using separate
 * renderers prevents the corruption of those escape sequences when interleaving the output streams.
 */
public class AnsiRenderer {

	/**
	 * These colors are taken from Terminal.app as documented on Wikipedia as of 26 April 2022.
	 * 
	 * <p>
	 * See <a href="https://en.wikipedia.org/wiki/ANSI_escape_code#3-bit_and_4-bit">ANSI escape
	 * code</a> on Wikipedia. They appear here in ANSI order.
	 */
	private static final Color[] BASIC_COLORS = {
		// standard colors
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.1"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.2"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.3"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.4"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.5"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.6"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.7"),
		new GColor("color.fg.plugin.interpreter.renderer.color.standard.8"),
		// high intensity colors
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.1"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.2"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.3"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.4"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.5"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.6"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.7"),
		new GColor("color.fg.plugin.interpreter.renderer.color.intense.8"),
	};
	/**
	 * This aids the implementation of the 6x6x6 color cube.
	 * 
	 * <p>
	 * These colors are numbered 16-231 inclusive. Incrementing by 1 brightens the blue channel.
	 * Incrementing by 6 brightens the green channel. Incrementing by 36 brightens the red channel.
	 * Each channel has 6 steps of brightness which are mapped to the 0-255 scale here.
	 */
	private static final int[] CUBE_STEPS = {
		0, 95, 135, 175, 215, 255
	};

	private class ParserHandler implements AnsiParserHandler {
		public StyledDocument document;
		public MutableAttributeSet attributes;

		@Override
		public void handleString(String text) throws BadLocationException {
			document.insertString(document.getLength(), text, attributes);
		}

		/**
		 * Get the 8-bit ANSI color.
		 * 
		 * <p>
		 * Colors 0-15 are the {@link AnsiRenderer#AnsiRenderer}: standard + high-intensity. Colors
		 * 16-231 come from a 6x6x6 RGB cube; see {@link AnsiRenderer#CUBE_STEPS}. Finally, colors
		 * 232-255 are 24 steps of gray scale.
		 * 
		 * @param v an 8-bit number
		 * @return the ANSI color
		 */
		private Color get256Color(int v) {
			if (v < 16) {
				return BASIC_COLORS[v];
			}
			else if (v < 232) {
				v -= 16;
				int b = v % 6;
				int g = (v / 6) % 6;
				int r = (v / 36) % 6;
				return ColorUtils.getColor(CUBE_STEPS[r], CUBE_STEPS[g], CUBE_STEPS[b]);
			}
			else if (v < 256) {
				v -= 232;
				int gray = v * 10 + 8;
				return ColorUtils.getColor(gray, gray, gray);
			}
			else {
				/* invalid */
				return BASIC_COLORS[0];
			}
		}

		/**
		 * Handler for a Select Graphic Rendition attribute (for CSI final byte {@code m})
		 * 
		 * <p>
		 * See <a href=
		 * "https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_(Select_Graphic_Rendition)_parameters">ANSI
		 * escape codes</a> on Wikipedia.
		 * 
		 * @param bits the semicolon-separated pieces, named {@code n} in the Wikipedia page.
		 * @param pos the index in {@code bits} to process next
		 * @return the number of {@code bits} processed (to advance before the next invocation)
		 * @throws NumberFormatException if a bit to process was not an integer (in decimal).
		 */
		private int handleSGRAttribute(String[] bits, int pos) throws NumberFormatException {
			int code = Integer.parseInt(bits[pos]);
			if (code >= 30 && code < 50) {
				/* Color codes */
				Object attributeName =
					(code < 40) ? StyleConstants.Foreground : StyleConstants.Background;
				int colorCode = code % 10;
				if (colorCode < 8) {
					/* 30-37, 40-47 - basic color */
					attributes.addAttribute(attributeName, BASIC_COLORS[colorCode]);
					return 1;
				}
				else if (colorCode == 8) {
					/* 38, 48 - extended color */
					if (pos + 1 >= bits.length) {
						/* Not enough extra parameters */
						return 1;
					}

					int colorType = Integer.parseInt(bits[pos + 1]);
					if (colorType == 5 && pos + 2 < bits.length) {
						int color = Integer.parseInt(bits[pos + 2]);
						attributes.addAttribute(attributeName, get256Color(color));
						return 3;
					}
					else if (colorType == 2 && pos + 4 < bits.length) {
						int r = Integer.parseInt(bits[pos + 2]);
						int g = Integer.parseInt(bits[pos + 3]);
						int b = Integer.parseInt(bits[pos + 4]);
						attributes.addAttribute(attributeName, ColorUtils.getColor(r, g, b));
						return 5;
					}
					return 1;
				}
				else if (colorCode == 9) {
					/* 39, 49 - default color */
					attributes.removeAttribute(attributeName);
					return 1;
				}
			}

			switch (code) {
				case 0:
					/* Reset parameters to default */
					attributes.removeAttributes(attributes);
					attributes.addAttributes(defaultAttributes);
					break;
				case 1:
					/* Bold or strong colour */
					StyleConstants.setBold(attributes, true);
					break;
				case 2:
					/* Faint or dim colour */
					StyleConstants.setBold(attributes, false);
					break;
				case 3:
					/* Italic */
					StyleConstants.setItalic(attributes, true);
					break;
				case 4:
					/* Underline */
					StyleConstants.setUnderline(attributes, true);
					break;
				case 5:
					/* Slow blink */
					break;
				case 6:
					/* Fast blink */
					break;
				case 7:
					/* Inverse video */
					// The default fg/bg may be different, and we don't have a way to know them.
					// Therefore, simply swapping the fg/bg won't work because if either of them
					// is unset, the result will not be predictable.
					// Instead, just ignore this directive.
					break;
				case 8:
					/* Conceal/hide */
					break;
				case 9:
					/* Strikethrough */
					StyleConstants.setStrikeThrough(attributes, true);
					break;
				/* 10-19: Various fonts, unsupported */
				case 20:
					/* Blackletter font */
					break;
				case 21:
					/* Double underline/not bold */
					StyleConstants.setUnderline(attributes, true);
					break;
				case 22:
					/* Normal intensity */
					StyleConstants.setBold(attributes, false);
					break;
				case 23:
					/* Not italic nor blackletter */
					StyleConstants.setItalic(attributes, false);
					break;
				case 24:
					/* Not underlined */
					StyleConstants.setUnderline(attributes, false);
					break;
				case 25:
					/* Not blinking */
					break;
				case 26:
					/* Proportional spacing */
					break;
				case 27:
					/* Not reversed video */
					break;
				case 28:
					/* Not hidden nor concealed */
					break;
				case 29:
					/* Not strikethrough */
					StyleConstants.setStrikeThrough(attributes, false);
					break;
			}
			return 1;
		}

		@Override
		public void handleCSI(String param, String inter, String finalChar)
				throws BadLocationException {
			if (finalChar.equals("m")) {
				/* Select Graphic Rendition */
				if (param.isEmpty()) {
					param = "0";
				}
				String[] bits = param.split("[:;]");
				int pos = 0;
				while (pos < bits.length) {
					try {
						int advance = handleSGRAttribute(bits, pos);
						pos += advance;
					}
					catch (NumberFormatException e) {
						pos += 1;
					}
				}
			}
			/* For now, ignore all other CSI commands */
		}

		@Override
		public void handleOSC(String param) throws BadLocationException {
			/* ignore OSC commands entirely */
		}
	}

	private final ParserHandler handler = new ParserHandler();
	private final AnsiParser parser = new AnsiParser(handler);

	private AttributeSet defaultAttributes = null;

	/**
	 * Render a string with embedded ANSI escape codes.
	 * 
	 * <p>
	 * The initial attributes object that is provided to this function will be used as the default
	 * style (e.g. after a ESC [ m).
	 * 
	 * <p>
	 * The instance may internally buffer some text. Use separate renderer objects for different
	 * text streams.
	 * 
	 * @param document Document to render the string to
	 * @param text A text string which may contain 7-bit ANSI escape codes
	 * @param attributes Current text attributes; may be modified by this function
	 * @throws BadLocationException if there is an error parsing the text
	 */
	public void renderString(StyledDocument document, String text, MutableAttributeSet attributes)
			throws BadLocationException {
		handler.document = document;
		handler.attributes = attributes;
		if (defaultAttributes == null) {
			defaultAttributes = attributes.copyAttributes();
		}
		parser.processString(text);
	}
}
