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

import java.awt.Color;

import ghidra.app.plugin.core.terminal.vt.VtHandler.AnsiColor;
import ghidra.app.plugin.core.terminal.vt.VtHandler.Intensity;

/**
 * A mechanism for converting an ANSI color specification to an AWT color.
 */
public interface AnsiColorResolver {

	/**
	 * A stupid name for a thing that is either the foreground or the background.
	 */
	enum WhichGround {
		FOREGROUND, BACKGROUND;
	}

	/**
	 * Convert a color specification to an AWT color
	 * 
	 * @param color the ANSI color specification
	 * @param ground identifies the colors use in the foreground or the background
	 * @param intensity gives the intensity of the color, really only used when a basic color is
	 *            specified.
	 * @param reverseVideo identifies whether the foreground and background colors were swapped,
	 *            really only used when the default color is specified.
	 * @return the AWT color, or null to not draw (usually in the case of the default background
	 *         color)
	 */
	Color resolveColor(AnsiColor color, WhichGround ground, Intensity intensity,
			boolean reverseVideo);
}
