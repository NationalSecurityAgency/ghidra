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
package ghidra.plugins.fsbrowser;

import java.util.*;

import javax.swing.Icon;

import generic.theme.*;
import ghidra.formats.gfilesystem.FSUtilities;
import resources.MultiIcon;

/**
 * Provides {@link Icon}s that represent the type and status of a file, based on
 * a filename mapping and caller specified status overlays.
 * <p>
 * The mappings between a file's extension and its icon are stored in a resource
 * file called "file_extension_icons.xml", which is read and parsed the first
 * time this service is referenced.
 * <p>
 * Status overlays are also specified in the file_extension_icons.xml file, and
 * are resized to be 1/2 the width and height of the icon they are being
 * overlaid on.
 * <p>
 * Thread safe
 * <p>
 */
public class FileIconService {

	private static final class Singleton {
		private static final FileIconService INSTANCE = new FileIconService();
	}

	public static FileIconService getInstance() {
		return Singleton.INSTANCE;
	}

	public static final Icon IMPORTED_OVERLAY_ICON =
		new GIcon("icon.fsbrowser.file.overlay.imported");
	public static final Icon FILESYSTEM_OVERLAY_ICON =
		new GIcon("icon.fsbrowser.file.overlay.filesystem");
	public static final Icon MISSING_PASSWORD_OVERLAY_ICON =
		new GIcon("icon.fsbrowser.file.overlay.missing.password");
	public static final Icon DEFAULT_ICON = new GIcon("icon.fsbrowser.file.extension.default");

	private static final String EXTENSION_ICON_PREFIX = "icon.fsbrowser.file.extension";
	private static final String SUBSTRING_ICON_PREFIX = "icon.fsbrowser.file.substring";

	private Map<String, Icon> substringToIconMap = new HashMap<>();

	private FileIconService() {
		createSubstringMap();
	}

	private void createSubstringMap() {
		GThemeValueMap values = ThemeManager.getInstance().getCurrentValues();
		List<IconValue> icons = values.getIcons();
		for (IconValue iconValue : icons) {
			String id = iconValue.getId();
			if (id.startsWith(SUBSTRING_ICON_PREFIX)) {
				String substring = id.substring(SUBSTRING_ICON_PREFIX.length());
				substringToIconMap.put(substring, new GIcon(id));
			}
		}
	}

	/**
	 * Returns an {@link Icon} that represents a file's content based on its
	 * name.
	 *
	 * @param fileName name of file that an icon is being requested for.
	 * @param overlays optional list of overlay icons that
	 *            should be overlaid on top of the base icon. These icons represent a
	 *            status or feature independent of the file's base icon.
	 * @return {@link Icon} instance that best represents the named file, never
	 *         null.
	 */
	public Icon getIcon(String fileName, List<Icon> overlays) {
		fileName = fileName.toLowerCase();
		String ext = FSUtilities.getExtension(fileName, 1);
		if (ext != null) {
			String iconId = EXTENSION_ICON_PREFIX + ext;
			if (Gui.hasIcon(iconId)) {
				Icon base = new GIcon(iconId);
				return buildIcon(base, overlays);
			}
		}

		for (String substring : substringToIconMap.keySet()) {
			if (fileName.indexOf(substring) != -1) {
				return buildIcon(substringToIconMap.get(substring), overlays);
			}
		}

		// return default icon for generic file
		return buildIcon(DEFAULT_ICON, overlays);
	}

	private Icon buildIcon(Icon base, List<Icon> overlays) {
		if (overlays == null || overlays.isEmpty()) {
			return base;
		}
		MultiIcon multiIcon = new MultiIcon(base);
		for (Icon overlay : overlays) {
			if (overlay != null) {
				multiIcon.addIcon(overlay);
			}
		}
		return multiIcon;
	}
}
