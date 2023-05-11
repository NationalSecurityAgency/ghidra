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
package resources;

import java.lang.reflect.Field;
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.theme.GIcon;
import ghidra.util.Msg;

/**
 * A class to get generic icons for standard actions.  All methods in this class return an 
 * icon that is 16x16 unless the method name ends in another size.'
 */
public class Icons {

	public static final Icon EMPTY_ICON = new GIcon("icon.empty");

	public static final Icon HELP_ICON = new GIcon("icon.help");

	public static final Icon ADD_ICON = new GIcon("icon.add");
	public static final Icon COPY_ICON = new GIcon("icon.copy");
	public static final Icon CUT_ICON = new GIcon("icon.cut");
	public static final Icon PASTE_ICON = new GIcon("icon.paste");

	public static final Icon COLLAPSE_ALL_ICON = new GIcon("icon.collapse.all");
	public static final Icon EXPAND_ALL_ICON = new GIcon("icon.expand.all");

	public static final Icon CONFIGURE_FILTER_ICON = new GIcon("icon.configure.filter");
	public static final Icon CLEAR_ICON = new GIcon("icon.clear");
	public static final Icon DELETE_ICON = new GIcon("icon.delete");
	public static final Icon ERROR_ICON = new GIcon("icon.error");

	public static final Icon HOME_ICON = new GIcon("icon.home");
	public static final Icon NAVIGATE_ON_INCOMING_EVENT_ICON = new GIcon("icon.navigate.in");
	public static final Icon NAVIGATE_ON_OUTGOING_EVENT_ICON = new GIcon("icon.navigate.out");

	public static final Icon NOT_ALLOWED_ICON = new GIcon("icon.not.allowed");
	public static final Icon OPEN_FOLDER_ICON = new GIcon("icon.folder.open");
	public static final Icon CLOSED_FOLDER_ICON = new GIcon("icon.folder.closed");
	public static final Icon REFRESH_ICON = new GIcon("icon.refresh");

	public static final Icon SORT_ASCENDING_ICON = new GIcon("icon.sort.ascending");
	public static final Icon SORT_DESCENDING_ICON = new GIcon("icon.sort.descending");

	public static final Icon STOP_ICON = new GIcon("icon.stop");
	public static final Icon STRONG_WARNING_ICON = new GIcon("icon.warning.strong");
	public static final Icon WARNING_ICON = new GIcon("icon.warning");
	public static final Icon INFO_ICON = new GIcon("icon.information");

	public static final Icon LEFT_ICON = new GIcon("icon.left");
	public static final Icon RIGHT_ICON = new GIcon("icon.right");
	public static final Icon UP_ICON = new GIcon("icon.up");
	public static final Icon DOWN_ICON = new GIcon("icon.down");

	/** An version of the LEFT_ICON with a different color */
	public static final Icon LEFT_ALTERNATE_ICON = new GIcon("icon.left.alt");

	/** An version of the RIGHT_ICON with a different color */
	public static final Icon RIGHT_ALTERNATE_ICON = new GIcon("icon.right.alt");

	public static final Icon SAVE_ICON = new GIcon("icon.save");
	public static final Icon SAVE_AS_ICON = new GIcon("icon.save.as");

	public static final Icon MAKE_SELECTION_ICON = new GIcon("icon.make.selection");

	public static final Icon ARROW_DOWN_RIGHT_ICON = new GIcon("icon.arrow.down.right");
	public static final Icon ARROW_UP_LEFT_ICON = new GIcon("icon.arrow.up.left");

	/**
	 * Returns true if the given string is a Java code snippet that references this class
	 * 
	 * @param snippet the string to check
	 * @return true if the given string is a Java code snippet that references this class
	 */
	public static boolean isIconsReference(String snippet) {
		return snippet.startsWith(Icons.class.getSimpleName());
	}

	/**
	 * Returns an {@link IconProvider} for the given string value, which is usually the 'src' 
	 * attribute of an IMG tag 
	 * 
	 * @param snippet the snippet
	 * @return the icon provider
	 */
	public static IconProvider getIconForIconsReference(String snippet) {

		String fieldName = getIconName(snippet);
		if (fieldName == null) {
			return null;
		}

		Icon icon = getIconByFieldName(fieldName);
		if (icon == null) {
			return null;
		}

		URL url = getUrlFromIcon(icon);
		return new IconProvider(icon, url);
	}

	/**
	 * Gets the icon for the given icon path. The given path should be relative to the classpath.
	 * If an icon by that name can't be found, the default "bomb" icon is returned instead.
	 * <P>
	 * For example, an icon named foo.png would typically be stored in the module at 
	 * "{modulePath}/src/main/resources/image/foo.png".  To reference that icon, use the path
	 * "images/foo.png", since "{modulePath}/src/main/resources" is in the classpath.
	 * 
	 * @param iconPath the icon path (relative to the classpath)
	 * @return The icon referenced by that path. 
	 */
	public static ImageIcon get(String iconPath) {
		return ResourceManager.loadImage(iconPath);
	}

	/**
	 * Gets the icon for the given icon path and scale it to the specified width and height.
	 * The given path should be relative to the classpath.
	 * If an icon by that name can't be found, the default "bomb" icon is returned instead.
	 * <P>
	 * For example, an icon named foo.png would typically be stored in the module at 
	 * "{modulePath}/src/main/resources/image/foo.png".  To reference that icon, use the path
	 * "images/foo.png", since "{modulePath}/src/main/resources" is in the classpath.
	 * 
	 * @param iconPath the icon path (relative to the classpath)
	 * @param width the desired width after scaling
	 * @param height the desired height after scaling
	 * @return The icon referenced by that path. 
	 */
	public static ImageIcon get(String iconPath, int width, int height) {
		return ResourceManager.loadImage(iconPath, width, height);
	}

	private static String getIconName(String snippet) {
		if (!isIconsReference(snippet)) {
			return null;
		}

		// +1 for the '.'
		String fieldName = snippet.substring(Icons.class.getSimpleName().length() + 1);
		return fieldName;
	}

	private static Icon getIconByFieldName(String fieldName) {

		try {
			Field field = Icons.class.getField(fieldName);
			Object object = field.get(Icons.class);
			Icon icon = (Icon) object;
			return icon;
		}
		catch (Exception e) {
			Msg.debug(Icons.class,
				"No icon named '" + fieldName + "' in class " + Icons.class.getName());
			return null;
		}
	}

	private static URL getUrlFromIcon(Icon icon) {
		if (icon instanceof GIcon gIcon) {
			URL url = gIcon.getUrl();
			if (url != null) {
				return url;
			}
			// this can happen for MultiIcons; leaving in for future debug
			// Msg.debug(Icons.class, "Unable to get URL for icon: " + icon, new Throwable());
		}
		return null;
	}

	private Icons() {
		// utility class
	}
}
