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
package ghidra.util.formatter;

import java.awt.Color;

import generic.theme.GColor;
import ghidra.util.HTMLUtilities;
import ghidra.util.WebColors;

public class InstructionHtmlAppender {
	private static final Color COLOR_FOREGROUND_ADDRESS =
		new GColor("color.fg.listing.address");
	private static final Color COLOR_FOREGROUND_REGISTER =
		new GColor("color.fg.listing.register");
	private static final Color COLOR_FOREGROUND_SCALAR =
		new GColor("color.fg.listing.constant");
	private static final Color COLOR_FOREGROUND_MNEMONIC =
		new GColor("color.fg.listing.mnemonic");
	private static final Color COLOR_FOREGROUND_SEPARATOR =
		new GColor("color.fg.listing.separator");
	private static final Color COLOR_FOREGROUND_BADREF =
		new GColor("color.fg.listing.ref.bad");
	private static final Color COLOR_FOREGROUND_VARIABLE =
		new GColor("color.fg.listing.function.variable");

	protected static String htmlColor(Color color, String display) {
		return String.format("<font color=\"%s\">%s</font>", WebColors.toString(color, false),
			HTMLUtilities.escapeHTML(display));
	}

	private final StringBuffer html = new StringBuffer("<html>");

	public void appendMnemonic(String mnemonic) {
		html.append(htmlColor(COLOR_FOREGROUND_MNEMONIC, mnemonic));
	}

	public void appendSeparator(String separator) {
		html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR, separator));
	}

	public void appendSeparator(Character separator) {
		html.append(htmlColor(COLOR_FOREGROUND_SEPARATOR,
			Character.toString(separator)));
	}

	public void appendBadRef(String error) {
		html.append(htmlColor(COLOR_FOREGROUND_BADREF, error));
	}

	public void appendRegister(String regname) {
		html.append(htmlColor(COLOR_FOREGROUND_REGISTER, regname));
	}

	public void appendScalar(String scalar) {
		html.append(htmlColor(COLOR_FOREGROUND_SCALAR, scalar));
	}

	public void appendAddress(String address) {
		html.append(htmlColor(COLOR_FOREGROUND_ADDRESS, address));
	}

	public void appendVariableRef(String variable) {
		html.append(htmlColor(COLOR_FOREGROUND_VARIABLE, variable));
	}

	public String finish() {
		html.append("</html>");
		return html.toString();
	}
}
