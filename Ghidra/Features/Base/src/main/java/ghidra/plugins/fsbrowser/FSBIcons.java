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
 * Static list of Icons for the file system browser plugin and its child windows.
 * <p>
 * The {@link #getInstance() singleton instance} provides {@link Icon}s that represent the type 
 * and status of a file, based on a filename mapping and caller specified status overlays.
 * <p>
 * Thread safe
 */
public class FSBIcons {
	//@formatter:off
	public static final Icon COPY = new GIcon("icon.plugin.fsbrowser.copy");
	public static final Icon CUT = new GIcon("icon.plugin.fsbrowser.cut");
	public static final Icon DELETE = new GIcon("icon.plugin.fsbrowser.delete");
	public static final Icon FONT = new GIcon("icon.plugin.fsbrowser.font");
	public static final Icon LOCKED = new GIcon("icon.plugin.fsbrowser.locked");
	public static final Icon NEW = new GIcon("icon.plugin.fsbrowser.new");
	public static final Icon PASTE = new GIcon("icon.plugin.fsbrowser.paste");
	public static final Icon REDO = new GIcon("icon.plugin.fsbrowser.redo");
	public static final Icon RENAME = new GIcon("icon.plugin.fsbrowser.rename");
	public static final Icon REFRESH = new GIcon("icon.plugin.fsbrowser.refresh");
	public static final Icon SAVE = new GIcon("icon.plugin.fsbrowser.save");
	public static final Icon SAVE_AS = new GIcon("icon.plugin.fsbrowser.save.as");
	public static final Icon UNDO = new GIcon("icon.plugin.fsbrowser.undo");
	public static final Icon UNLOCKED = new GIcon("icon.plugin.fsbrowser.unlocked");
	public static final Icon CLOSE = new GIcon("icon.plugin.fsbrowser.close");
	public static final Icon COLLAPSE_ALL = new GIcon("icon.plugin.fsbrowser.collapse.all");
	public static final Icon COMPRESS = new GIcon("icon.plugin.fsbrowser.compress");
	public static final Icon CREATE_FIRMWARE = new GIcon("icon.plugin.fsbrowser.create.firmware");
	public static final Icon EXPAND_ALL = new GIcon("icon.plugin.fsbrowser.expand.all");
	public static final Icon EXTRACT = new GIcon("icon.plugin.fsbrowser.extract");
	public static final Icon INFO = new GIcon("icon.plugin.fsbrowser.info");
	public static final Icon OPEN = new GIcon("icon.plugin.fsbrowser.open");
	public static final Icon OPEN_AS_BINARY = new GIcon("icon.plugin.fsbrowser.open.as.binary");
	public static final Icon OPEN_IN_LISTING = new GIcon("icon.plugin.fsbrowser.open.in.listing");
	public static final Icon OPEN_FILE_SYSTEM = new GIcon("icon.plugin.fsbrowser.open.file.system");
	public static final Icon PHOTO = new GIcon("icon.plugin.fsbrowser.photo");
	public static final Icon VIEW_AS_IMAGE = new GIcon("icon.plugin.fsbrowser.view.as.image");
	public static final Icon VIEW_AS_TEXT = new GIcon("icon.plugin.fsbrowser.view.as.text");
	public static final Icon ECLIPSE = new GIcon("icon.plugin.fsbrowser.eclipse");
	public static final Icon JAR = new GIcon("icon.plugin.fsbrowser.jar");
	public static final Icon IMPORT = new GIcon("icon.plugin.fsbrowser.import");
	public static final Icon iOS = new GIcon("icon.plugin.fsbrowser.ios");
	public static final Icon OPEN_ALL = new GIcon("icon.plugin.fsbrowser.open.all");
	public static final Icon LIST_MOUNTED = new GIcon("icon.plugin.fsbrowser.list.mounted");
	public static final Icon LIBRARY = new GIcon("icon.plugin.fsbrowser.library");
	
	public static final Icon IMPORTED_OVERLAY_ICON = new GIcon("icon.fsbrowser.file.overlay.imported");
	public static final Icon FILESYSTEM_OVERLAY_ICON = new GIcon("icon.fsbrowser.file.overlay.filesystem");
	public static final Icon MISSING_PASSWORD_OVERLAY_ICON = new GIcon("icon.fsbrowser.file.overlay.missing.password");
	public static final Icon LINK_OVERLAY_ICON = new GIcon("icon.fsbrowser.file.overlay.link");
	public static final Icon DEFAULT_ICON = new GIcon("icon.fsbrowser.file.extension.default");
	//@formatter:on

	public static FSBIcons getInstance() {
		return Singleton.INSTANCE;
	}

	private static final class Singleton {
		private static final FSBIcons INSTANCE = new FSBIcons();
	}

	private static final String EXTENSION_ICON_PREFIX = "icon.fsbrowser.file.extension";
	private static final String SUBSTRING_ICON_PREFIX = "icon.fsbrowser.file.substring";

	private Map<String, Icon> substringToIconMap = createSubstringMap();

	private FSBIcons() {
		// don't create instances of this class, use getInstance() instead
	}

	private Map<String, Icon> createSubstringMap() {
		Map<String, Icon> results = new HashMap<>();
		GThemeValueMap values = ThemeManager.getInstance().getCurrentValues();
		List<IconValue> icons = values.getIcons();
		for (IconValue iconValue : icons) {
			String id = iconValue.getId();
			if (id.startsWith(SUBSTRING_ICON_PREFIX)) {
				String substring = id.substring(SUBSTRING_ICON_PREFIX.length());
				results.put(substring, new GIcon(id));
			}
		}
		return results;
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
