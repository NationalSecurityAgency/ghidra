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
import java.awt.Color;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.MutableAttributeSet;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

interface AnsiParserHandler {
    default void handleString(String text) throws BadLocationException{
    }

    default void handleCSI(String param, String inter, String finalchar) throws BadLocationException {
    }

    default void handleOSC(String param) throws BadLocationException {
    }
}

class AnsiParser {
    /* A 7-bit CSI sequence consists of ESC [, followed by any number of parameter characters
       in the range 0x30-0x3f, followed by any number of intermediate characters in the range
       0x20-0x2f, followed by a single final character in the range 0x40-0x7e. */
    private static final String CSI_PARAM_EXPR = "[\\x30-\\x3F]*";
    private static final String CSI_INTER_EXPR = "[\\x20-\\x2F]*";
    private static final String CSI_FINAL_EXPR = "[\\x40-\\x7E]";
    /* A regex to match a complete CSI sequence and parse the pieces as groups */
    private static final String CSI_MATCH_EXPR = String.format(
        "\\x1b\\[(?<CSIPARAM>%s)(?<CSIINTER>%s)(?<CSIFINAL>%s)",
        CSI_PARAM_EXPR,
        CSI_INTER_EXPR,
        CSI_FINAL_EXPR
    );
    /* A regex to match an unfinished CSI sequence at the end of the input */
    private static final String CSI_TAIL_EXPR = String.format(
        "\\x1b(?:\\[(?:%s(?:%s)?)?)?\\z",
        CSI_PARAM_EXPR,
        CSI_INTER_EXPR
    );

    /* A 7-bit OSC sequence consists of ESC ], followed by any number of non-control parameter
       characters, followed by a BEL character \x07 or the ST sequence ESC \ */
    private static final String OSC_PARAM_EXPR = "[\\x20-\\x7F]*";
    /* A regex to match a complete OSC sequence and extract the parameter as a group */
    private static final String OSC_MATCH_EXPR = String.format(
        "\\x1b\\](?<OSCPARAM>%s)(?:\\x07|\\x1b\\\\)",
        OSC_PARAM_EXPR
    );
    /* A regex to match an unfinished OSC sequence at the end of the input */
    private static final String OSC_TAIL_EXPR = String.format(
        "\\x1b(?:\\](?:%s(?:\\x1b)?)?)?\\z",
        OSC_PARAM_EXPR
    );

    /* A combined regex to match a complete control sequence */
    private static final Pattern CTRL_SEQ = Pattern.compile(String.format(
        "(?<CSI>%s)|(?<OSC>%s)|(?<NUL>\\x00)",
        CSI_MATCH_EXPR,
        OSC_MATCH_EXPR
    ));

    /* A combined regex to match an unfinished control sequence */
    private static final Pattern CTRL_TAIL = Pattern.compile(String.format(
        "%s|%s",
        CSI_TAIL_EXPR,
        OSC_TAIL_EXPR
    ));

    private String buffer = "";
    private AnsiParserHandler handler;

    public AnsiParser(AnsiParserHandler handler) {
        this.handler = handler;
    }

    public void processString(String text) throws BadLocationException {
        text = buffer + text;
        Matcher m = CTRL_SEQ.matcher(text);
        int lastPos = 0;
        while(m.find()) {
            if(m.start() > lastPos)
                handler.handleString(text.substring(lastPos, m.start()));
            if(m.group("CSI") != null) {
                handler.handleCSI(m.group("CSIPARAM"), m.group("CSIINTER"), m.group("CSIFINAL"));
            } else if(m.group("OSC") != null) {
                handler.handleOSC(m.group("OSCPARAM"));
            } else if(m.group("NUL") != null) {
                // Suppress NUL bytes from the output.
                // TTY commands, such as "clear", that see TERM=vt100
                // may append NUL padding to their output, which a real vt100 would need.
            }
            lastPos = m.end();
        }

        m = CTRL_TAIL.matcher(text);
        if(m.find(lastPos)) {
            if(lastPos < m.start())
                handler.handleString(text.substring(lastPos, m.start()));
            buffer = text.substring(m.start());
        } else {
            if(lastPos < text.length())
                handler.handleString(text.substring(lastPos));
            buffer = "";
        }
    }
}

public class AnsiRenderer {
    private static final Color[] BASIC_COLORS = {
        new Color(0, 0, 0),
        new Color(194, 54, 33),
        new Color(37, 188, 36),
        new Color(173, 173, 39),
        new Color(73, 46, 225),
        new Color(211, 56, 211),
        new Color(51, 187, 200),
        new Color(203, 204, 205),

        new Color(129, 131, 131),
        new Color(252, 57, 31),
        new Color(49, 231, 34),
        new Color(234, 236, 35),
        new Color(88, 51, 255),
        new Color(249, 53, 248),
        new Color(20, 240, 240),
        new Color(233, 235, 235),
    };
    private static final int[] CUBE_COORDS = {
        0, 95, 135, 175, 215, 255
    };

    private class ParserHandler implements AnsiParserHandler {
        public StyledDocument document;
        public MutableAttributeSet attributes;

        @Override
        public void handleString(String text) throws BadLocationException {
            document.insertString(document.getLength(), text, attributes);
        }

        private Color get256Color(int v) {
            if(v < 16) {
                return BASIC_COLORS[v];
            } else if(v < 232) {
                v -= 16;
                int b = v % 6;
                int g = (v / 6) % 6;
                int r = (v / 36) % 6;
                return new Color(CUBE_COORDS[r], CUBE_COORDS[g], CUBE_COORDS[b]);
            } else if(v < 256) {
                v -= 232;
                int gray = v * 10 + 8;
                return new Color(gray, gray, gray);
            } else {
                /* invalid */
                return BASIC_COLORS[0];
            }
        }

        private int handleSGR(String[] bits, int pos) throws NumberFormatException {
            int code = Integer.parseInt(bits[pos]);
            if(code >= 30 && code < 50) {
                /* Colour codes */
                Object attributeName = (code < 40) ? StyleConstants.Foreground : StyleConstants.Background;
                int colorCode = code % 10;
                if(colorCode < 8) {
                    /* 30-37, 40-47 - basic color */
                    attributes.addAttribute(attributeName, BASIC_COLORS[colorCode]);
                    return 1;
                } else if(colorCode == 8) {
                    /* 38, 48 - extended color */
                    if(pos + 1 >= bits.length) {
                        /* Not enough extra parameters */
                        return 1;
                    }

                    int colorType = Integer.parseInt(bits[pos + 1]);
                    if(colorType == 5 && pos + 2 < bits.length) {
                        int color = Integer.parseInt(bits[pos + 2]);
                        attributes.addAttribute(attributeName, get256Color(color));
                        return 3;
                    } else if(colorType == 2 && pos + 4 < bits.length) {
                        int r = Integer.parseInt(bits[pos + 2]);
                        int g = Integer.parseInt(bits[pos + 3]);
                        int b = Integer.parseInt(bits[pos + 4]);
                        attributes.addAttribute(attributeName, new Color(r, g, b));
                        return 5;
                    }
                    return 1;
                } else if(colorCode == 9) {
                    /* 39, 49 - default color */
                    attributes.removeAttribute(attributeName);
                    return 1;
                }
            }

            switch(code) {
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
        public void handleCSI(String param, String inter, String finalchar) throws BadLocationException {
            if(finalchar.equals("m")) {
                /* Select Graphic Rendition */
                if(param.isEmpty()) {
                    param = "0";
                }
                String[] bits = param.split("[:;]");
                int pos = 0;
                while(pos < bits.length) {
                    try {
                        int advance = handleSGR(bits, pos);
                        pos += advance;
                    } catch(NumberFormatException e) {
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
    private AttributeSet defaultAttributes = null;
    private ParserHandler handler = new ParserHandler();
    private AnsiParser parser = new AnsiParser(handler);

    /** Render a string with embedded ANSI escape codes.
     * @param document Document to render the string to
     * @param text A text string which may contain 7-bit ANSI escape codes
     * @param attributes Current text attributes; may be modified by this function
     *
     * The initial attributes object that is provided to this function will be used
     * as the default style (e.g. after a ESC [ m).
     * The instance may internally buffer some text. Use separate renderer objects
     * for different text streams.
     */
    void renderString(StyledDocument document, String text, MutableAttributeSet attributes) throws BadLocationException {
        handler.document = document;
        handler.attributes = attributes;
        if(defaultAttributes == null) {
            defaultAttributes = attributes.copyAttributes();
        }
        parser.processString(text);
    }
}
