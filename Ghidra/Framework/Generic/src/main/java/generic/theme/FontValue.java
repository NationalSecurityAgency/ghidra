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

import ghidra.util.Msg;

/**
 * A class for storing {@link Font} values that have a String id (e.g. font.foo.bar) and either
 * a concrete font or a reference id which is the String id of another FontValue that it
 * will inherit its font from. So if this class's font value is non-null, the refId will be null
 * and if the class's refId is non-null, then the font value will be null.
 */
public class FontValue extends ThemeValue<Font> {
	static final String FONT_ID_PREFIX = "font.";
	public static final Font LAST_RESORT_DEFAULT = new Font("monospaced", Font.PLAIN, 12);
	private static final String EXTERNAL_PREFIX = "[font]";

	/**
	 * Constructor used when the FontValue will have a direct {@link Font} value. The refId
	 * will be null.
	 * @param id the id for this FontValue
	 * @param value the {@link Font} to associate with the given id
	 */
	public FontValue(String id, Font value) {
		super(id, null, value);
	}

	/**
	 * Constructor used when the FontValue will inherit its {@link Font} from another FontValue. The
	 * font value field will be null.
	 * @param id the id for this FontValue
	 * @param refId the id of another FontValue that this FontValue will inherit from
	 */
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

	/** 
	 * Returns true if the given key string is a valid external key for a font value
	 * @param key the key string to test
	 * @return true if the given key string is a valid external key for a font value
	 */
	public static boolean isFontKey(String key) {
		return key.startsWith(FONT_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

}
