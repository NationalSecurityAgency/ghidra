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

import ghidra.app.plugin.core.terminal.vt.VtCharset.G;
import ghidra.app.plugin.core.terminal.vt.VtHandler.KeyMode;

public enum VtState {
	/**
	 * The initial state, just process output characters until we encounter an {@code ESC}.
	 */
	CHAR {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			if (b == 0x1b) {
				return ESC;
			}
			handler.handleCharExc(b);
			return CHAR;
		}
	},
	/**
	 * We have just encountered an {@code ESC}.
	 */
	ESC {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			switch (b) {
				case '7':
					handler.handleSaveCursorPos();
					return CHAR;
				case '8':
					handler.handleRestoreCursorPos();
					return CHAR;
				case '(':
					parser.csG = G.G0;
					return CHARSET;
				case ')':
					parser.csG = G.G1;
					return CHARSET;
				case '*':
					parser.csG = G.G2;
					return CHARSET;
				case '+':
					parser.csG = G.G3;
					return CHARSET;
				case '[':
					return CSI_PARAM;
				case ']':
					return OSC_PARAM;
				case '=':
					handler.handleKeypadMode(KeyMode.APPLICATION);
					return CHAR;
				case '>':
					handler.handleKeypadMode(KeyMode.NORMAL);
					return CHAR;
				case 'D':
					handler.handleScrollViewportDown(1, true);
					return CHAR;
				case 'M':
					handler.handleScrollViewportUp(1);
					return CHAR;
				case 'c':
					handler.handleFullReset();
					return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			handler.handleCharExc(b);
			return CHAR;
		}
	},
	/**
	 * We have encountered {@code ESC} and a charset-selection byte. Now we just need to know the
	 * charset. Most are one byte, but there are some two-byte codes.
	 */
	CHARSET {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			switch (b) {
				case '"':
					return CHARSET_QUOTE;
				case '%':
					return CHARSET_PERCENT;
				case '&':
					return CHARSET_AMPERSAND;
				case 'A':
					handler.handleSetCharset(parser.csG, VtCharset.UK);
					return CHAR;
				case 'B':
					handler.handleSetCharset(parser.csG, VtCharset.USASCII);
					return CHAR;
				case 'C':
				case '5':
					handler.handleSetCharset(parser.csG, VtCharset.FINNISH);
					return CHAR;
				case 'H':
				case '7':
					handler.handleSetCharset(parser.csG, VtCharset.SWEDISH);
					return CHAR;
				case 'K':
					handler.handleSetCharset(parser.csG, VtCharset.GERMAN);
					return CHAR;
				case 'Q':
				case '9':
					handler.handleSetCharset(parser.csG, VtCharset.FRENCH_CANADIAN);
					return CHAR;
				case 'R':
				case 'f':
					handler.handleSetCharset(parser.csG, VtCharset.FRENCH);
					return CHAR;
				case 'Y':
					handler.handleSetCharset(parser.csG, VtCharset.ITALIAN);
					return CHAR;
				case 'Z':
					handler.handleSetCharset(parser.csG, VtCharset.SPANISH);
					return CHAR;
				case '4':
					handler.handleSetCharset(parser.csG, VtCharset.DUTCH);
					return CHAR;
				case '=':
					handler.handleSetCharset(parser.csG, VtCharset.SWISS);
					return CHAR;
				case '`':
				case 'E':
				case '6':
					handler.handleSetCharset(parser.csG, VtCharset.NORWEGIAN_DANISH);
					return CHAR;
				case '0':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SPECIAL_LINES);
					return CHAR;
				case '<':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SUPPLEMENTAL);
					return CHAR;
				case '>':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_TECHNICAL);
					return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcessByte(parser.doProcessByte(CHAR, parser.csG.b), b);
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code "}.
	 */
	CHARSET_QUOTE {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			switch (b) {
				case '>':
					handler.handleSetCharset(parser.csG, VtCharset.GREEK);
					return CHAR;
				case '4':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_HEBREW);
					return CHAR;
				case '?':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_GREEK);
					return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcessByte(
				parser.doProcessByte(parser.doProcessByte(CHAR, parser.csG.b), (byte) '"'), b);
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code %}.
	 */
	CHARSET_PERCENT {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			switch (b) {
				case '2':
					handler.handleSetCharset(parser.csG, VtCharset.TURKISH);
					return CHAR;
				case '6':
					handler.handleSetCharset(parser.csG, VtCharset.PORTUGESE);
					return CHAR;
				case '=':
					handler.handleSetCharset(parser.csG, VtCharset.HEBREW);
					return CHAR;
				case '0':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_TURKISH);
					return CHAR;
				case '5':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SUPPLEMENTAL_GRAPHICS);
					return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcessByte(
				parser.doProcessByte(parser.doProcessByte(CHAR, parser.csG.b), (byte) '%'), b);
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code &}.
	 */
	CHARSET_AMPERSAND {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			switch (b) {
				case '4':
					handler.handleSetCharset(parser.csG, VtCharset.DEC_CYRILLIC);
					return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcessByte(
				parser.doProcessByte(parser.doProcessByte(CHAR, parser.csG.b), (byte) '&'), b);
		}
	},
	/**
	 * We've encountered {@code CSI}, so now we're parsing parameters, intermediates, or the final
	 * character.
	 */
	CSI_PARAM {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			if (0x30 <= b && b <= 0x3f) {
				parser.csiParam.put(b);
				return CSI_PARAM;
			}
			if (0x20 <= b && b <= 0x2f) {
				parser.csiInter.put(b);
				return CSI_INTER;
			}
			if (0x40 <= b && b <= 0x7e) {
				handleCsi(b, parser, handler);
				return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcess(CHAR, parser.copyCsiBuffer(b));
		}
	},
	/**
	 * We've finished (or skipped) parsing CSI parameters, so now we're parsing intermediates or the
	 * final character.
	 */
	CSI_INTER {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			if (0x20 <= b && b <= 0x2f) {
				parser.csiInter.put(b);
				return CSI_INTER;
			}
			if (0x40 <= b && b <= 0x7e) {
				handleCsi(b, parser, handler);
				return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcess(CHAR, parser.copyCsiBuffer(b));
		}
	},
	/**
	 * We've encountered {@code OSC}, so now we're parsing parameters until we encounter {@code BEL}
	 * or {@code ST}.
	 */
	OSC_PARAM {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			// For whatever reason, Windows includes the null terminator in titles
			if (0x20 <= b && b <= 0x7f || b == 0) {
				parser.oscParam.put(b);
				return OSC_PARAM;
			}
			if (b == 0x07) {
				handleOsc(parser, handler);
				return CHAR;
			}
			if (b == 0x1b) {
				return OSC_ESC;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcess(CHAR, parser.copyOscBuffer(b));
		}
	},
	/**
	 * We've encountered {@code ESC} part of , so now we're parsing parameters until we encounter
	 * {@code BEL} or {@code ST}.
	 */
	OSC_ESC {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			if (b == '\\') {
				handleOsc(parser, handler);
				return CHAR;
			}
			handler.handleCharExc((byte) 0x1b);
			return parser.doProcessByte(OSC_PARAM, b);
		}
	};

	/**
	 * Handle the given character
	 * 
	 * @param b the character currently being parsed
	 * @param parser the parser
	 * @param handler the handler
	 * @return the resulting machine state
	 */
	protected abstract VtState handleNext(byte b, VtParser parser, VtHandler handler);

	/**
	 * Handle a CSI sequence
	 * 
	 * @param csiFinal the final byte
	 * @param parser the parser
	 * @param handler the handler
	 */
	protected void handleCsi(byte csiFinal, VtParser parser, VtHandler handler) {
		parser.csiParam.flip();
		parser.csiInter.flip();
		handler.handleCsiExc(parser.csiParam, parser.csiInter, csiFinal);
		parser.csiParam.clear();
		parser.csiInter.clear();
	}

	/**
	 * Handle an OSC sequence
	 * 
	 * @param parser the parser
	 * @param handler the handler
	 */
	protected void handleOsc(VtParser parser, VtHandler handler) {
		parser.oscParam.flip();
		handler.handleOscExc(parser.oscParam);
		parser.oscParam.clear();
	}
}
