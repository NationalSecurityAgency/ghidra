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

import ghidra.util.Msg;

/**
 * A Java property value for keys that use String values.
 */
public class StringPropertyValue extends JavaPropertyValue {

	private static final String EXTERNAL_LAF_ID_PREFIX = "[laf.string]";

	public StringPropertyValue(String id, String value) {
		this(id, null, value);
	}

	public StringPropertyValue(String id, String refId, String value) {
		super(id, refId, value);
	}

	public static boolean isStringKey(String key) {
		return key.toLowerCase().startsWith(EXTERNAL_LAF_ID_PREFIX);
	}

	public static StringPropertyValue parse(String key, String value) {
		String id = fromExternalId(key);

		if (isStringKey(value)) {
			String refId = fromExternalId(value);
			return new StringPropertyValue(id, refId, null);
		}

		return new StringPropertyValue(id, value);
	}

	private static String fromExternalId(String externalId) {
		if (!externalId.toLowerCase().startsWith(EXTERNAL_LAF_ID_PREFIX)) {
			return externalId;
		}

		// We return the raw property name (e.g., TextArea.background), not the normalized name
		// (e.g., laf.color.TextArea.background), since the system currently does not provide the
		// end-user a way to change these values from the UI.
		return externalId.substring(EXTERNAL_LAF_ID_PREFIX.length());
	}

	@Override
	protected Object getUnresolvedReferenceValue(String primaryId, String unresolvedId) {
		Msg.warn(this,
			"Could not resolve indirect property for \"" + unresolvedId +
				"\" for primary id \"" + primaryId + "\", using last resort default");
		return "";
	}

	@Override
	protected String toExternalId(String internalId) {
		return EXTERNAL_LAF_ID_PREFIX + internalId;
	}

	@Override
	protected String getSerializedValue() {
		return String.valueOf(value);
	}
}
