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

import java.awt.Color;

import ghidra.util.Msg;
import ghidra.util.WebColors;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A class for storing {@link Color} values that have a String id (e.g. color.bg.foo) and either
 * a concrete color or a reference id which is the String id of another ColorValue that it
 * will inherit its color from. So if this class's color value is non-null, the refId will be null
 * and if the class's refId is non-null, then the color value will be null.
 */
public class ColorValue extends ThemeValue<Color> {
	private static final String COLOR_ID_PREFIX = "color.";
	private static final String EXTERNAL_PREFIX = "[color]";

	public static final Color LAST_RESORT_DEFAULT = new Color(128, 128, 128);

	/**
	 * Constructor used when the ColorValue will have a direct {@link Color} value. The refId will
	 * be null. Note: if a {@link GColor} is passed in as the value, then this will be an indirect
	 * ColorValue that inherits its color from the id stored in the GColor.
	 * @param id the id for this ColorValue
	 * @param value the {@link Color} to associate with the given id
	 */
	public ColorValue(String id, Color value) {
		super(id, getRefId(value), getRawColor(value));
	}

	/**
	 * Constructor used when the ColorValue will inherit its color from another ColorValue. The
	 * color value field will be null.
	 * @param id the id for this ColorValue
	 * @param refId the id of another ColorValue that this ColorValue will inherit from
	 */
	public ColorValue(String id, String refId) {
		super(id, refId, null);
	}

	@Override
	public String getSerializationString() {
		String outputId = toExternalId(id);
		return outputId + " = " + getSerializedValue();
	}

	@Override
	public boolean isExternal() {
		return !id.startsWith(COLOR_ID_PREFIX);
	}

	/** 
	 * Returns true if the given key string is a valid external key for a color value
	 * @param key the key string to test
	 * @return true if the given key string is a valid external key for a color value
	 */
	public static boolean isColorKey(String key) {
		return key.startsWith(COLOR_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	/**
	 * Parses the value string into a color or reference and creates a new ColorValue using
	 * the given key and the parse results.
	 * @param key the key to associate the parsed value with
	 * @param value the color value to parse
	 * @return a ColorValue with the given key and the parsed value
	 */
	public static ColorValue parse(String key, String value) {
		String id = fromExternalId(key);
		if (isColorKey(value)) {
			return new ColorValue(id, fromExternalId(value));
		}
		Color color = WebColors.getColor(value);
		return color == null ? null : new ColorValue(id, color);
	}

	@Override
	protected ColorValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getColor(refId);
	}

	@Override
	protected Color getUnresolvedReferenceValue(String primaryId, String unresolvedId) {

		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan(getClass());
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, "docking.theme", "classfinder",
				"Application", "ghidra.GhidraRun", "java.lang.Class", "java.lang.Thread");
		t.setStackTrace(filtered);

		Msg.error(this, "Could not resolve indirect color path for \"" + unresolvedId +
			"\" for primary id \"" + primaryId + "\", using last resort default", t);

		return LAST_RESORT_DEFAULT;
	}

	private static String toExternalId(String internalId) {
		if (internalId.startsWith(COLOR_ID_PREFIX)) {
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

	private static Color getRawColor(Color value) {
		if (value instanceof GColor) {
			return null;
		}
		return value;
	}

	private static String getRefId(Color value) {
		if (value instanceof GColor) {
			return ((GColor) value).getId();
		}
		return null;
	}

	private String getSerializedValue() {
		if (referenceId != null) {
			return toExternalId(referenceId);
		}
		String outputString = WebColors.toString(value, false);
		String colorName = WebColors.toWebColorName(value);
		if (colorName != null) {
			outputString += " // " + colorName;
		}
		return outputString;
	}

	@Override
	public void installValue(ThemeManager themeManager) {
		themeManager.setColor(this);
	}

}
