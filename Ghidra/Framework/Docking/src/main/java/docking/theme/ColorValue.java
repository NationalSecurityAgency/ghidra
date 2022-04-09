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
package docking.theme;

import java.awt.Color;

import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;

public class ColorValue extends ThemeValue<Color> {
	static final String COLOR_ID_PREFIX = "color.";
	static final String EXTERNAL_PREFIX = "[color]";

	public static final Color LAST_RESORT_DEFAULT = Color.GRAY;

	public ColorValue(String id, Color value) {
		super(id, null, value);
	}

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
	protected String getIdPrefix() {
		return COLOR_ID_PREFIX;
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

	public static boolean isColorKey(String key) {
		return key.startsWith(COLOR_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	@Override
	protected int compareValues(Color v1, Color v2) {
		int alpha1 = v1.getAlpha();
		int alpha2 = v2.getAlpha();

		if (alpha1 == alpha2) {
			return getHsbCompareValue(v1) - getHsbCompareValue(v2);
		}
		return alpha1 - alpha2;
	}

	private int getHsbCompareValue(Color v) {
		// compute a value the compares colors first by hue, then saturation, then brightness
		// reduce noise by converting float values from 0-1 to integers 0 - 7
		float[] hsb = Color.RGBtoHSB(v.getRed(), v.getGreen(), v.getBlue(), null);
		return 100 * (int) (10 * hsb[0]) + 10 * (int) (10 * hsb[1]) + (int) (10 * hsb[2]);
	}
}
