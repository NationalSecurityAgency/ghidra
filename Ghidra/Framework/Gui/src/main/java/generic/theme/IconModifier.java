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

import java.awt.Dimension;
import java.awt.Point;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
//font.foo = images/flag.png[size(12,16)][move(3,4)][disable]

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.*;

/**
 * Class that can transform one icon into another. Useful for scaling, translating, disabling,
 * or overlaying an icon.
 */

public class IconModifier {
	Dimension size;
	Point translation;
	boolean disabled;
	Integer rotation;
	boolean mirror;	// mirrors the image left to right
	boolean flip;   // flips the image upside down
	List<IconValue> overlayIconValues = null;

	/**
	 * Creates an IconModifier that can scale, translate, or disable an icon.
	 * @param size if non-null, scales an icon to this size.
	 * @param translation if non-null, translates an icon by this amount
	 * @param rotation if non-null, the amount in degrees to rotate the icon
	 * @param disabled if true, creates a disabled version of the icon
	 * @param mirror if true, the image will have its x values swapped (left to right)
	 * @param flip if true, the image will have its y values swapped (turned upside down)
	 */
	public IconModifier(Dimension size, Point translation, Integer rotation,
			boolean disabled, boolean mirror, boolean flip) {
		this.size = size;
		this.translation = translation;
		this.rotation = rotation;
		this.disabled = disabled;
		this.mirror = mirror;
		this.flip = flip;
	}

	private IconModifier() {

	}

	/**
	 * Sets size modifier. Icons that are modified by this IconModifier will be scaled to this size.
	 * @param size the size to scale modified icons.
	 */
	public void setSizeModifier(Dimension size) {
		this.size = size;
	}

	/**
	 * Sets the translation for this modifier. Icons that are modified by this IconModifier will
	 * be translated by the amount of the given point.
	 * @param point the x,y amount to translate an image
	 */
	public void setMoveModifier(Point point) {
		this.translation = point;
	}

	/**
	 * Sets the rotation for this modifier. Icons that are modified by this IconModifier will
	 * be rotated by the given amount (in degrees)
	 * @param degrees the rotation amount;
	 */
	public void setRotationModifer(int degrees) {
		this.rotation = degrees;
	}

	/**
	 * Sets this modifier to disable an icon
	 */
	public void setDisabled() {
		disabled = true;
	}

	/**
	 * Sets the modifier to flip the icon side to side
	 */
	public void setMirror() {
		mirror = true;
	}

	/**
	 * Sets the modifier to flip the icon side to side
	 */
	public void setFlip() {
		flip = true;
	}

	/**
	 * Modifies the given icon by the any of the modifiers set.
	 * @param icon the icon to be modified
	 * @param values the ThemeValueMap needed if the modify action is to overlay other icons. The 
	 * values are used to resolve indirect overlay icon references
	 * @return A new Icon that is a modified version of the given icon
	 */
	public Icon modify(Icon icon, GThemeValueMap values) {
		Icon modified = icon;
		if (size != null) {
			modified = ResourceManager.getScaledIcon(modified, size.width, size.height);
		}
		if (disabled) {
			modified = ResourceManager.getDisabledIcon(modified);
		}
		if (mirror) {
			modified = new ReflectedIcon(modified, true);
		}
		if (flip) {
			modified = new ReflectedIcon(modified, false);
		}
		if (rotation != null) {
			modified = new RotateIcon(modified, rotation);
		}
		if (translation != null) {
			modified = new TranslateIcon(modified, translation.x, translation.y);
		}
		if (overlayIconValues != null) {
			MultiIcon multiIcon = new MultiIcon(modified);
			for (IconValue iconValue : overlayIconValues) {
				multiIcon.addIcon(iconValue.get(values));
			}
			modified = multiIcon;
		}
		return modified;
	}

	/**
	 * Returns a string that can be parsed by the {@link #parse(String)} method of this class
	 * @return a string that can be parsed by the {@link #parse(String)} method of this class
	 */
	public String getSerializationString() {
		StringBuilder builder = new StringBuilder();
		if (size != null) {
			builder.append("[" + "size(" + size.width + "," + size.height + ")]");
		}
		if (mirror) {
			builder.append("[mirror]");
		}
		if (flip) {
			builder.append("[flip]");
		}
		if (rotation != null) {
			builder.append("[rotate(" + rotation + ")]");
		}
		if (translation != null) {
			builder.append("[" + "move(" + translation.x + "," + translation.y + ")]");
		}
		if (disabled) {
			builder.append("[disabled]");
		}
		return builder.toString();
	}

	/**
	 * Parses the given string as one or more icon modifiers
	 * @param iconModifierString the string to parse as modifiers
	 * @return an IconModifier as specified by the given string
	 * @throws ParseException if the iconModifierString in not properly formatted icon modifier
	 */
	public static IconModifier parse(String iconModifierString) throws ParseException {
		if (iconModifierString.isBlank()) {
			return null;
		}
		IconModifier modifier = new IconModifier();
		String baseModifierString = getBaseModifierString(iconModifierString);
		parseBaseModifiers(modifier, baseModifierString);

		String overlayValuesString = getIconOverlaysString(iconModifierString);
		parseOverlayModifiers(modifier, overlayValuesString);
		if (modifier.hadModifications()) {
			return modifier;
		}
		return null;
	}

	private static void parseOverlayModifiers(IconModifier modifier, String overlayValuesString)
			throws ParseException {
		List<String> overlayModifierStrings =
			ThemeValueUtils.parseGroupings(overlayValuesString, '{', '}');
		for (String overlayIconString : overlayModifierStrings) {
			IconValue overlayIconValue = IconValue.parse("", overlayIconString);
			modifier.addOverlayIcon(overlayIconValue);
		}
	}

	private void addOverlayIcon(IconValue overlayIconValue) {
		if (overlayIconValues == null) {
			overlayIconValues = new ArrayList<>();
		}
		overlayIconValues.add(overlayIconValue);
	}

	private static void parseBaseModifiers(IconModifier modifier, String baseModifierString)
			throws ParseException {
		List<String> modifierValues = ThemeValueUtils.parseGroupings(baseModifierString, '[', ']');
		for (String modifierString : modifierValues) {
			modifierString = modifierString.replaceAll("\\s", "").toLowerCase();

			if (modifierString.startsWith("size")) {
				parseSizeModifier(modifier, modifierString);
			}
			else if (modifierString.startsWith("move")) {
				parseMoveModifier(modifier, modifierString);
			}
			else if (modifierString.startsWith("mirror")) {
				parseMirrorModifier(modifier, modifierString);
			}
			else if (modifierString.startsWith("flip")) {
				parseFlipModifier(modifier, modifierString);
			}
			else if (modifierString.startsWith("rotate")) {
				parseRotateModifier(modifier, modifierString);
			}
			else if (modifierString.startsWith("disabled")) {
				parseDisabledModifier(modifier, modifierString);
			}
			else {
				throw new ParseException("Invalid icon modifier: " + modifierString, 0);
			}
		}
	}

	private static String getBaseModifierString(String value) {
		int overlayStart = value.indexOf("{");
		if (overlayStart < 0) {
			return value;
		}
		if (overlayStart == 0) {
			return "";
		}
		return value.substring(0, overlayStart);
	}

	private static String getIconOverlaysString(String value) {
		int overlayStart = value.indexOf("{");
		if (overlayStart >= 0) {
			return value.substring(overlayStart);
		}
		return "";
	}

	private boolean hadModifications() {
		return size != null || translation != null || overlayIconValues != null ||
			rotation != null || disabled || mirror || flip;
	}

	private static void parseDisabledModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		if (!modifierString.equals("disabled")) {
			throw new ParseException("Illegal Icon modifier: " + modifier, 0);
		}
		modifier.setDisabled();
	}

	private static void parseMirrorModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		if (!modifierString.equals("mirror")) {
			throw new ParseException("Illegal Icon modifier: " + modifier, 0);
		}
		modifier.setMirror();
	}

	private static void parseFlipModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		if (!modifierString.equals("flip")) {
			throw new ParseException("Illegal Icon modifier: " + modifier, 0);
		}
		modifier.setFlip();
	}

	private static void parseRotateModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		String argsString = modifierString.substring("rotate".length());
		int rotation = parseIntArg(argsString);
		modifier.setRotationModifer(rotation);
	}

	private static void parseMoveModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		String argsString = modifierString.substring("move".length());
		Point argValue = parsePointArgs(argsString);
		modifier.setMoveModifier(argValue);
	}

	private static void parseSizeModifier(IconModifier modifier, String modifierString)
			throws ParseException {
		String argsString = modifierString.substring("size".length());
		Point argValue = parsePointArgs(argsString);
		modifier.setSizeModifier(new Dimension(argValue.x, argValue.y));
	}

	private static Point parsePointArgs(String argsString) throws ParseException {
		if (!(argsString.startsWith("(") && argsString.endsWith(")"))) {
			throw new ParseException("Invalid arguments: " + argsString, 0);
		}
		argsString = argsString.substring(1, argsString.length() - 1);
		String[] split = argsString.split(",");
		if (split.length != 2) {
			throw new ParseException("Invalid arguments: " + argsString, 0);
		}
		try {
			int arg1 = Integer.parseInt(split[0]);
			int arg2 = Integer.parseInt(split[1]);
			return new Point(arg1, arg2);
		}
		catch (NumberFormatException e) {
			throw new ParseException("Invalid arguments: " + argsString, 0);
		}
	}

	private static int parseIntArg(String argString) throws ParseException {
		if (!(argString.startsWith("(") && argString.endsWith(")"))) {
			throw new ParseException("Invalid arguments: " + argString, 0);
		}
		argString = argString.substring(1, argString.length() - 1);
		try {
			return Integer.parseInt(argString);
		}
		catch (NumberFormatException e) {
			throw new ParseException("Invalid arguments: " + argString, 0);
		}
	}

}
