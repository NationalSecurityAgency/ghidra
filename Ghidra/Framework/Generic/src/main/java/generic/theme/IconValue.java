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

import javax.swing.Icon;

import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * A class for storing {@link Icon} values that have a String id (e.g. icon.bg.foo) and either
 * a concrete icon or a reference id which is the String id of another IconValue that it
 * will inherit its icon from. So if this class's icon value is non-null, the refId will be null
 * and if the class's refId is non-null, then the icon value will be null.
 */
public class IconValue extends ThemeValue<Icon> {
	static final String ICON_ID_PREFIX = "icon.";

	public static final String LAST_RESORT_DEFAULT = "images/bomb.gif";

	private static final String EXTERNAL_PREFIX = "[icon]";

	/**
	 * Constructor used when the ColorValue will have a direct {@link Icon} value. The refId will
	 * be null. Note: if a {@link GIcon} is passed in as the value, then this will be an indirect
	 * IconValue that inherits its icon from the id stored in the GIcon.
	 * @param id the id for this IconValue
	 * @param icon the {@link Icon} to associate with the given id
	 */
	public IconValue(String id, Icon icon) {
		super(id, getRefId(icon), getRawIcon(icon));
		if (icon instanceof GIcon) {
			throw new IllegalArgumentException("Can't use GIcon as the value!");
		}

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

	/** 
	 * Returns true if the given key string is a valid external key for an icon value
	 * @param key the key string to test
	 * @return true if the given key string is a valid external key for an icon value
	 */
	public static boolean isIconKey(String key) {
		return key.startsWith(ICON_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
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
}
