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
			return switch (b) {
				case '7' -> {
					handler.handleSaveCursorPos();
					yield CHAR;
				}
				case '8' -> {
					handler.handleRestoreCursorPos();
					yield CHAR;
				}
				case '(' -> {
					parser.csG = G.G0;
					yield CHARSET;
				}
				case ')' -> {
					parser.csG = G.G1;
					yield CHARSET;
				}
				case '*' -> {
					parser.csG = G.G2;
					yield CHARSET;
				}
				case '+' -> {
					parser.csG = G.G3;
					yield CHARSET;
				}
				case 'P' -> DCS_PARAM;
				case '[' -> CSI_PARAM;
				case ']' -> OSC_PARAM;
				case '\\' -> CHAR; // ST, just go back to CHAR
				case '=' -> {
					handler.handleKeypadMode(KeyMode.APPLICATION);
					yield CHAR;
				}
				case '>' -> {
					handler.handleKeypadMode(KeyMode.NORMAL);
					yield CHAR;
				}
				case 'D' -> {
					handler.handleScrollViewportDown(1, true);
					yield CHAR;
				}
				case 'M' -> {
					handler.handleScrollViewportUp(1);
					yield CHAR;
				}
				case 'c' -> {
					handler.handleFullReset();
					yield CHAR;
				}
				default -> {
					handler.handleCharExc((byte) 0x1b); // Is this correct?
					yield parser.doProcessByte(CHAR, b);
				}
			};
		}
	},
	/**
	 * We have encountered {@code ESC} and a charset-selection byte. Now we just need to know the
	 * charset. Most are one byte, but there are some two-byte codes.
	 */
	CHARSET {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			return switch (b) {
				case '"' -> CHARSET_QUOTE;
				case '%' -> CHARSET_PERCENT;
				case '&' -> CHARSET_AMPERSAND;
				case 'A' -> {
					handler.handleSetCharset(parser.csG, VtCharset.UK);
					yield CHAR;
				}
				case 'B' -> {
					handler.handleSetCharset(parser.csG, VtCharset.USASCII);
					yield CHAR;
				}
				case 'C', '5' -> {
					handler.handleSetCharset(parser.csG, VtCharset.FINNISH);
					yield CHAR;
				}
				case 'H', '7' -> {
					handler.handleSetCharset(parser.csG, VtCharset.SWEDISH);
					yield CHAR;
				}
				case 'K' -> {
					handler.handleSetCharset(parser.csG, VtCharset.GERMAN);
					yield CHAR;
				}
				case 'Q', '9' -> {
					handler.handleSetCharset(parser.csG, VtCharset.FRENCH_CANADIAN);
					yield CHAR;
				}
				case 'R', 'f' -> {
					handler.handleSetCharset(parser.csG, VtCharset.FRENCH);
					yield CHAR;
				}
				case 'Y' -> {
					handler.handleSetCharset(parser.csG, VtCharset.ITALIAN);
					yield CHAR;
				}
				case 'Z' -> {
					handler.handleSetCharset(parser.csG, VtCharset.SPANISH);
					yield CHAR;
				}
				case '4' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DUTCH);
					yield CHAR;
				}
				case '=' -> {
					handler.handleSetCharset(parser.csG, VtCharset.SWISS);
					yield CHAR;
				}
				case '`', 'E', '6' -> {
					handler.handleSetCharset(parser.csG, VtCharset.NORWEGIAN_DANISH);
					yield CHAR;
				}
				case '0' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SPECIAL_LINES);
					yield CHAR;
				}
				case '<' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SUPPLEMENTAL);
					yield CHAR;
				}
				case '>' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_TECHNICAL);
					yield CHAR;
				}
				default -> {
					handler.handleCharExc((byte) 0x1b);
					VtState st = CHAR;
					st = parser.doProcessByte(st, parser.csG.b);
					st = parser.doProcessByte(st, b);
					yield st;
				}
			};
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code "}.
	 */
	CHARSET_QUOTE {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			return switch (b) {
				case '>' -> {
					handler.handleSetCharset(parser.csG, VtCharset.GREEK);
					yield CHAR;
				}
				case '4' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_HEBREW);
					yield CHAR;
				}
				case '?' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_GREEK);
					yield CHAR;
				}
				default -> {
					handler.handleCharExc((byte) 0x1b);
					VtState st = CHAR;
					st = parser.doProcessByte(st, parser.csG.b);
					st = parser.doProcessByte(st, (byte) '"');
					st = parser.doProcessByte(st, b);
					yield st;
				}
			};
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code %}.
	 */
	CHARSET_PERCENT {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			return switch (b) {
				case '2' -> {
					handler.handleSetCharset(parser.csG, VtCharset.TURKISH);
					yield CHAR;
				}
				case '6' -> {
					handler.handleSetCharset(parser.csG, VtCharset.PORTUGESE);
					yield CHAR;
				}
				case '=' -> {
					handler.handleSetCharset(parser.csG, VtCharset.HEBREW);
					yield CHAR;
				}
				case '0' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_TURKISH);
					yield CHAR;
				}
				case '5' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_SUPPLEMENTAL_GRAPHICS);
					yield CHAR;
				}
				default -> {
					handler.handleCharExc((byte) 0x1b);
					VtState st = CHAR;
					st = parser.doProcessByte(st, parser.csG.b);
					st = parser.doProcessByte(st, (byte) '%');
					st = parser.doProcessByte(st, b);
					yield st;
				}
			};
		}
	},
	/**
	 * We're selecting a two-byte charset, and we just encountered {@code &}.
	 */
	CHARSET_AMPERSAND {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			return switch (b) {
				case '4' -> {
					handler.handleSetCharset(parser.csG, VtCharset.DEC_CYRILLIC);
					yield CHAR;
				}
				default -> {
					handler.handleCharExc((byte) 0x1b);
					VtState st = CHAR;
					st = parser.doProcessByte(st, parser.csG.b);
					st = parser.doProcessByte(st, (byte) '&');
					st = parser.doProcessByte(st, b);
					yield st;
				}
			};
		}
	},
	/**
	 * We've encountered {@code DCS}
	 * <p>
	 * This implementation is entirely incorrect, but it's here to clean up all the VT-100 (or not)
	 * garbage that Claude Code emits.
	 */
	DCS_PARAM {
		@Override
		protected VtState handleNext(byte b, VtParser parser, VtHandler handler) {
			return switch (b) {
				case 0x1b -> CHAR; // This is really supposed to be terminated by ST (ESC \)
				default -> DCS_PARAM;
			};
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
				parser.putCsiParamByte(b);
				return CSI_PARAM;
			}
			if (0x20 <= b && b <= 0x2f) {
				parser.putCsiInterByte(b);
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
				parser.putCsiInterByte(b);
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
				parser.putOscParamByte(b);
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
	 * We've encountered the {@code ESC} part of {@code OSC}, so now we're parsing parameters until
	 * we encounter {@code BEL} or {@code ST}.
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
