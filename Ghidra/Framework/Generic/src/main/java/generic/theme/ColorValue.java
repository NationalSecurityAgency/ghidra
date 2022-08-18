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
import utilities.util.reflection.ReflectionUtilities;

/**
 * A class for storing {@link Color} values that have a String id (e.g. color.bg.foo) and either
 * a concrete color or a reference id which is the String id of another ColorValue that it
 * will inherit its color from. So if this class's color value is non-null, the refId will be null
 * and if the class's refId is non-null, then the color value will be null.
 */
public class ColorValue extends ThemeValue<Color> {
	static final String COLOR_ID_PREFIX = "color.";
	static final String EXTERNAL_PREFIX = "[color]";

	public static final Color LAST_RESORT_DEFAULT = Color.GRAY;

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
	protected ColorValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getColor(refId);
	}

	@Override
	protected Color getUnresolvedReferenceValue(String id) {

		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan();
		StackTraceElement[] trace = t.getStackTrace();
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, "docking.theme", "classfinder",
				"Application", "ghidra.GhidraRun", "java.lang.Class", "java.lang.Thread");
		t.setStackTrace(filtered);

		Msg.error(this,
			"Could not resolve indirect color for \"" + id + "\", using last resort default!", t);
		return LAST_RESORT_DEFAULT;
	}

	@Override
	public String toExternalId(String internalId) {
		if (internalId.startsWith(COLOR_ID_PREFIX)) {
			return internalId;
		}
		return EXTERNAL_PREFIX + internalId;
	}

	@Override
	public String fromExternalId(String externalId) {
		if (externalId.startsWith(EXTERNAL_PREFIX)) {
			return externalId.substring(EXTERNAL_PREFIX.length());
		}
		return externalId;
	}

	/** 
	 * Returns true if the given key string is a valid external key for a color value
	 * @param key the key string to test
	 * @return true if the given key string is a valid external key for a color value
	 */
	public static boolean isColorKey(String key) {
		return key.startsWith(COLOR_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
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

}
