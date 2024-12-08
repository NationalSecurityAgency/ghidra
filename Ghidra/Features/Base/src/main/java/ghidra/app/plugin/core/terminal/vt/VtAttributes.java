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

import ghidra.app.plugin.core.terminal.vt.AnsiColorResolver.WhichGround;
import ghidra.app.plugin.core.terminal.vt.VtHandler.*;

/**
 * A tuple of attributes to apply when rendering terminal text.
 * 
 * <p>
 * These are set and collected as the parser and handler deal with various ANSI VT escape codes. As
 * characters are placed in the buffer, the current attributes are applied to the corresponding
 * cells. The renderer then has to apply the attributes appropriately as it renders each character
 * in the buffer.
 */
public record VtAttributes(AnsiColor fg, AnsiColor bg, Intensity intensity,
		AnsiFont font, Underline underline, Blink blink, boolean reverseVideo, boolean hidden,
		boolean strikeThrough, boolean proportionalSpacing) {

	/**
	 * The default attributes: plain white on black, usually.
	 */
	public static final VtAttributes DEFAULTS =
		new VtAttributes(AnsiDefaultColor.INSTANCE, AnsiDefaultColor.INSTANCE,
			Intensity.NORMAL, AnsiFont.NORMAL, Underline.NONE, Blink.NONE, false, false, false,
			false);

	/**
	 * Create a copy of this record with the foreground color replaced
	 * 
	 * @param fg the new foreground color
	 * @return the new record
	 */
	public VtAttributes fg(AnsiColor fg) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the background color replaced
	 * 
	 * @param bg the new background color
	 * @return the new record
	 */
	public VtAttributes bg(AnsiColor bg) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the intensity replaced
	 * 
	 * @param intensity the new intensity
	 * @return the new record
	 */
	public VtAttributes intensity(Intensity intensity) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the font replaced
	 * 
	 * @param font the new font
	 * @return the new record
	 */
	public VtAttributes font(AnsiFont font) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the underline replaced
	 * 
	 * @param underline the new underline
	 * @return the new record
	 */
	public VtAttributes underline(Underline underline) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the blink replaced
	 * 
	 * @param blink the new blink
	 * @return the new record
	 */
	public VtAttributes blink(Blink blink) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the reverse-video replaced
	 * 
	 * @param reverseVideo the new reverse-video
	 * @return the new record
	 */
	public VtAttributes reverseVideo(boolean reverseVideo) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the hidden replaced
	 * 
	 * @param hidden the new hidden
	 * @return the new record
	 */
	public VtAttributes hidden(boolean hidden) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the strike-through replaced
	 * 
	 * @param strikeThrough the new strike-through
	 * @return the new record
	 */
	public VtAttributes strikeThrough(boolean strikeThrough) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Create a copy of this record with the proportional-spacing replaced
	 * 
	 * @param proportionalSpacing the new proportional-spacing
	 * @return the new record
	 */
	public VtAttributes proportionalSpacing(boolean proportionalSpacing) {
		return new VtAttributes(fg, bg, intensity, font, underline, blink, reverseVideo,
			hidden, strikeThrough, proportionalSpacing);
	}

	/**
	 * Resolve the foreground color for these attributes
	 * 
	 * @param colors the color resolver
	 * @return the color
	 */
	public Color resolveForeground(AnsiColorResolver colors) {
		return colors.resolveColor(reverseVideo ? bg : fg, WhichGround.FOREGROUND, intensity,
			reverseVideo);
	}

	/**
	 * Resolve the background color for these attributes
	 * 
	 * @param colors the color resolver
	 * @return the color, or null to not paint the background
	 */
	public Color resolveBackground(AnsiColorResolver colors) {
		return colors.resolveColor(reverseVideo ? fg : bg, WhichGround.BACKGROUND, Intensity.NORMAL,
			reverseVideo);
	}
}
