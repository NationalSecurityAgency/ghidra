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

import javax.swing.Icon;

import ghidra.util.Msg;
import resources.ResourceManager;

public class IconValue extends ThemeValue<Icon> {
	static final String ICON_ID_PREFIX = "icon.";

	public static final String LAST_RESORT_DEFAULT = "images/bomb.gif";

	private static final String EXTERNAL_PREFIX = "[icon]";

	public IconValue(String id, Icon icon) {
		super(id, null, icon);
	}

	public IconValue(String id, String refId) {
		super(id, refId, null);
	}

	@Override
	protected IconValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getIcon(refId);
	}

	@Override
	protected Icon getUnresolvedReferenceValue(String id) {
		Msg.warn(this,
			"Could not resolve indirect icon path for" + id + ", using last resort default");
		return ResourceManager.getDefaultIcon();
	}

	@Override
	protected String getIdPrefix() {
		return ICON_ID_PREFIX;
	}

	@Override
	public String toExternalId(String internalId) {
		if (internalId.startsWith(ICON_ID_PREFIX)) {
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

	public static boolean isIconKey(String key) {
		return key.startsWith(ICON_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	@Override
	protected int compareValues(Icon v1, Icon v2) {
		return v1.toString().compareTo(v2.toString());
	}
}
