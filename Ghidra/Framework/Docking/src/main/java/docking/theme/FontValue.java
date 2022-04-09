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

import java.awt.Font;

import ghidra.util.Msg;

public class FontValue extends ThemeValue<Font> {
	static final String FONT_ID_PREFIX = "font.";
	public static final Font LAST_RESORT_DEFAULT = new Font("monospaced", Font.PLAIN, 12);
	private static final String EXTERNAL_PREFIX = "[font]";

	public FontValue(String id, Font value) {
		super(id, null, value);
	}

	public FontValue(String id, String refId) {
		super(id, refId, null);
	}

	@Override
	protected FontValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getFont(refId);
	}

	@Override
	protected Font getUnresolvedReferenceValue(String id) {
		Msg.warn(this, "Could not resolve indirect font for" + id + ", using last resort default");
		return LAST_RESORT_DEFAULT;
	}

	@Override
	protected String getIdPrefix() {
		return FONT_ID_PREFIX;
	}

	@Override
	public String toExternalId(String internalId) {
		if (internalId.startsWith(FONT_ID_PREFIX)) {
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

	public static boolean isFontKey(String key) {
		return key.startsWith(FONT_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	@Override
	protected int compareValues(Font v1, Font v2) {
		return v1.toString().compareTo(v2.toString());
	}
}
