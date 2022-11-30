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

import java.text.ParseException;

import javax.swing.Icon;

import ghidra.util.Msg;
import resources.ResourceManager;
import resources.icons.EmptyIcon;
import resources.icons.UrlImageIcon;

/**
 * A class for storing {@link Icon} values that have a String id (e.g. icon.bg.foo) and either
 * a concrete icon or a reference id which is the String id of another IconValue that it
 * will inherit its icon from. So if this class's icon value is non-null, the refId will be null
 * and if the class's refId is non-null, then the icon value will be null.
 */
public class IconValue extends ThemeValue<Icon> {
	private static final String EMPTY_ICON_STRING = "EMPTY_ICON";

	static final String ICON_ID_PREFIX = "icon.";

	public static final Icon LAST_RESORT_DEFAULT = ResourceManager.getDefaultIcon();

	private static final String EXTERNAL_PREFIX = "[icon]";

	private static final int STANDARD_EMPTY_ICON_SIZE = 16;

	private IconModifier modifier;

	/**
	 * Constructor used when the ColorValue will have a direct {@link Icon} value. The refId will
	 * be null. Note: if a {@link GIcon} is passed in as the value, then this will be an indirect
	 * IconValue that inherits its icon from the id stored in the GIcon.
	 * @param id the id for this IconValue
	 * @param icon the {@link Icon} to associate with the given id
	 */
	public IconValue(String id, Icon icon) {
		super(id, getRefId(icon), getRawIcon(icon));
	}

	/**
	 * Constructor used when the IconValue will inherit its {@link Icon} from another IconValue. The
	 * icon value field will be null.
	 * @param id the id for this IconValue
	 * @param refId the id of another IconValue that this IconValue will inherit from
	 */
	public IconValue(String id, String refId) {
		super(id, refId, null);
	}

	private IconValue(String id, String refId, IconModifier modifier) {
		super(id, refId, null);
		this.modifier = modifier;
	}

	private IconValue(String id, Icon icon, IconModifier modifier) {
		super(id, null, icon);
		this.modifier = modifier;
	}

	@Override
	public Icon get(GThemeValueMap values) {
		Icon icon = super.get(values);
		if (modifier != null) {
			return modifier.modify(icon, values);
		}
		return icon;
	}

	@Override
	public String getSerializationString() {
		String outputId = toExternalId(id);
		return outputId + " = " + getValueOutput();
	}

	/** 
	* Returns true if the given key string is a valid external key for an icon value
	* @param key the key string to test
	* @return true if the given key string is a valid external key for an icon value
	*/
	public static boolean isIconKey(String key) {
		return key.startsWith(ICON_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	/**
	 * Converts an icon to a string.
	 * @param icon the icon to convert to a String
	 * @return a String that represents the icon
	 */
	public static String iconToString(Icon icon) {
		if (icon instanceof EmptyIcon) {
			int iconWidth = icon.getIconWidth();
			int iconHeight = icon.getIconHeight();
			if (iconWidth == STANDARD_EMPTY_ICON_SIZE && iconHeight == STANDARD_EMPTY_ICON_SIZE) {
				return EMPTY_ICON_STRING;
			}
			return EMPTY_ICON_STRING + "[size(" + iconWidth + "," + iconHeight + ")]";
		}

		if (icon instanceof UrlImageIcon urlIcon) {
			return urlIcon.getOriginalPath();
		}
		return GTheme.JAVA_ICON;
	}

	/**
	 * Parses the value string into an icon or reference and creates a new IconValue using
	 * the given key and the parse results.
	 * @param key the key to associate the parsed value with
	 * @param value the color value to parse
	 * @return an IconValue with the given key and the parsed value
	 * @throws ParseException if the value can't be parsed
	 */
	public static IconValue parse(String key, String value) throws ParseException {
		String id = fromExternalId(key);
		if (isIconKey(value)) {
			return parseRefIcon(id, value);
		}
		return parseIcon(id, value);
	}

	private static IconValue parseIcon(String id, String value) throws ParseException {
		int modifierIndex = getModifierIndex(value);

		if (modifierIndex < 0) {
			if (value.isBlank()) {
				return null;
			}
			return new IconValue(id, getIcon(value));
		}

		String baseIconString = value.substring(0, modifierIndex).trim();
		if (baseIconString.isBlank()) {
			return null;
		}
		Icon icon = getIcon(baseIconString);
		String iconModifierString = value.substring(modifierIndex);
		IconModifier modifier = IconModifier.parse(iconModifierString);
		return new IconValue(id, icon, modifier);
	}

	private static Icon getIcon(String baseIconString) throws ParseException {
		if (EMPTY_ICON_STRING.equals(baseIconString)) {
			return new EmptyIcon(STANDARD_EMPTY_ICON_SIZE, STANDARD_EMPTY_ICON_SIZE);
		}
		Icon icon = ResourceManager.loadIcon(baseIconString);
		if (icon == null) {
			throw new ParseException("Can't find icon for \"" + baseIconString + "\"", 0);
		}
		return icon;
	}

	private static IconValue parseRefIcon(String id, String value) throws ParseException {
		if (value.startsWith(EXTERNAL_PREFIX)) {
			value = value.substring(EXTERNAL_PREFIX.length());
		}
		int modifierIndex = getModifierIndex(value);
		if (modifierIndex < 0) {
			return new IconValue(id, value);
		}
		String refId = value.substring(0, modifierIndex).trim();
		IconModifier modifier = IconModifier.parse(value.substring(modifierIndex));
		return new IconValue(id, refId, modifier);
	}

	private static int getModifierIndex(String value) {
		int baseModifierIndex = value.indexOf("[", 1);  // start past first char as it could be valid "[EXTERNAL]" prefix
		int overlayModifierIndex = value.indexOf("{");
		if (baseModifierIndex < 0) {
			return overlayModifierIndex;
		}
		if (overlayModifierIndex < 0) {
			return baseModifierIndex;
		}
		return Math.min(overlayModifierIndex, baseModifierIndex);
	}

	@Override
	protected IconValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getIcon(refId);
	}

	@Override
	protected Icon getUnresolvedReferenceValue(String id, String unresolvedId) {
		Msg.warn(this,
			"Could not resolve indirect icon path for \"" + unresolvedId +
				"\" for primary id \"" + id + "\", using last resort default");
		return LAST_RESORT_DEFAULT;
	}

	private static String toExternalId(String internalId) {
		if (internalId.startsWith(ICON_ID_PREFIX)) {
			return internalId;
		}
		return EXTERNAL_PREFIX + internalId;
	}

	private static String fromExternalId(String externalId) {
		if (externalId.startsWith(EXTERNAL_PREFIX)) {
			return externalId.substring(EXTERNAL_PREFIX.length());
		}
		return externalId;
	}

	private static Icon getRawIcon(Icon value) {
		if (value instanceof GIcon) {
			return null;
		}
		return value;
	}

	private static String getRefId(Icon value) {
		if (value instanceof GIcon) {
			return ((GIcon) value).getId();
		}
		return null;
	}

	private String getValueOutput() {
		String outputString = null;
		if (referenceId != null) {
			outputString = toExternalId(referenceId);
		}
		else {
			outputString = iconToString(value);
		}
		if (modifier != null) {
			outputString += modifier.getSerializationString();
		}
		return outputString;
	}

	@Override
	public void installValue(ThemeManager themeManager) {
		themeManager.setIcon(this);
	}

}
