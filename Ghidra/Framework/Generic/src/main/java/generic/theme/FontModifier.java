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
package generic.theme;

import java.awt.Font;
import java.util.*;
import java.util.regex.Pattern;

public class FontModifier {

	private static final Pattern MODIFIER_PATTERN = Pattern.compile("(\\[([a-zA-Z]+|[0-9]+)\\])*");
	private String family;
	private Integer style;
	private Integer size;

	public FontModifier() {

	}

	public FontModifier(String family, Integer style, Integer size) {
		this.family = family;
		this.style = style;
		this.size = size;
	}

	public void addFamilyModifier(String newFamily) {
		if (family != null) {
			throw new IllegalStateException("Multiple font family names specified");
		}
		this.family = newFamily;
	}

	public void addSizeModfier(int newSize) {
		if (size != null) {
			throw new IllegalStateException("Multiple font sizes specified");
		}
		this.size = newSize;
	}

	public void addStyleModifier(int newStyle) {
		if (style == null) {
			style = newStyle;
			return;
		}
		if (style == Font.PLAIN || newStyle == Font.PLAIN) {
			throw new IllegalStateException("Attempted to set incompable styles");
		}
		style = style | newStyle;
	}

	public Font modify(Font font) {
		if (family == null) {
			if (style != null && size != null) {
				return font.deriveFont(style, size);
			}
			else if (style != null) {
				return font.deriveFont(style);
			}
			return font.deriveFont((float) size);
		}
		int newStyle = style != null ? style : font.getStyle();
		int newSize = size != null ? size : font.getSize();
		return new Font(family, newStyle, newSize);
	}

	public static FontModifier parse(String value) {
		List<String> modifierValues = getModifierPieces(value);
		if (modifierValues.isEmpty()) {
			return null;
		}
		FontModifier modifier = new FontModifier();
		for (String modifierString : modifierValues) {
			if (setSize(modifier, modifierString)) {
				continue;
			}
			if (setStyle(modifier, modifierString)) {
				continue;
			}
			modifier.addFamilyModifier(modifierString);
		}
		if (modifier.hadModifications()) {
			return modifier;
		}
		return null;
	}

	public String getSerializationString() {
		StringBuilder builder = new StringBuilder();
		if (family != null) {
			builder.append("[" + family + "]");
		}
		if (size != null) {
			builder.append("[" + size + "]");
		}
		if (style != null) {
			switch (style.intValue()) {
				case Font.PLAIN:
					builder.append("[plain]");
					break;
				case Font.BOLD:
					builder.append("[bold]");
					break;
				case Font.ITALIC:
					builder.append("[italic]");
					break;
				case Font.BOLD | Font.ITALIC:
					builder.append("[bold][italic]");
					break;
			}
		}

		return builder.toString();
	}

	private boolean hadModifications() {
		return family != null || size != null || style != null;
	}

	private static boolean setStyle(FontModifier modifier, String modifierString) {
		int style = FontValue.getStyle(modifierString);
		if (style >= 0) {
			modifier.addStyleModifier(style);
			return true;
		}
		return false;
	}

	private static boolean setSize(FontModifier modifier, String modifierString) {
		try {
			int size = Integer.parseInt(modifierString);
			modifier.addSizeModfier(size);
			return true;
		}
		catch (NumberFormatException e) {
			return false;
		}
	}

	private static List<String> getModifierPieces(String value) {
		if (!MODIFIER_PATTERN.matcher(value).matches()) {
			throw new IllegalArgumentException("Invalid font modifier string");
		}
		StringTokenizer tokenizer = new StringTokenizer(value, "[]");
		List<String> list = new ArrayList<>();
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken().trim();
			if (!token.isBlank()) {
				list.add(token);
			}
		}
		return list;
	}
}
