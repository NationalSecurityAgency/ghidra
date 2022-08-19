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

import java.awt.*;
import java.lang.reflect.Field;
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.theme.GIcon;
import ghidra.util.Msg;
import resources.icons.RotateIcon;
import resources.icons.TranslateIcon;

/**
 * A class to get generic icons for standard actions.  All methods in this class return an 
 * icon that is 16x16 unless the method name ends in another size.'
 */
public class Icons {

	public static final Icon EMPTY_ICON = new GIcon("icon.empty");

	public static final Icon HELP_ICON = new GIcon("icon.help");

	public static final Icon ADD_ICON = new GIcon("icon.add");

	public static final Icon COLLAPSE_ALL_ICON = new GIcon("icon.collapse.all");
	public static final Icon EXPAND_ALL_ICON = new GIcon("icon.expand.all");

	public static final Icon CONFIGURE_FILTER_ICON = new GIcon("icon.configure.filter");
	public static final Icon DELETE_ICON = new GIcon("icon.delete");
	public static final Icon ERROR_ICON = new GIcon("icon.error");

	public static final Icon NAVIGATE_ON_INCOMING_EVENT_ICON = new GIcon("icon.navigate.in");
	public static final Icon NAVIGATE_ON_OUTGOING_EVENT_ICON = new GIcon("icon.navigate.out");

	public static final Icon NOT_ALLOWED_ICON = new GIcon("icon.notallowed");
	public static final Icon OPEN_FOLDER_ICON = new GIcon("icon.folder.open");
	public static final Icon REFRESH_ICON = new GIcon("icon.refresh");

	public static final Icon SORT_ASCENDING_ICON = new GIcon("icon.sort.ascending");
	public static final Icon SORT_DESCENDING_ICON = new GIcon("icon.sort.descending");

	public static final Icon STOP_ICON = new GIcon("icon.stop");
	public static final Icon STRONG_WARNING_ICON = new GIcon("icon.warning.strong");

	public static final Icon LEFT_ICON = new GIcon("icon.left");
	public static final Icon RIGHT_ICON = new GIcon("icon.right");

	/** An version of the LEFT_ICON with a different color */
	public static final Icon LEFT_ALTERNATE_ICON = new GIcon("icon.left.alt");

	/** An version of the RIGHT_ICON with a different color */
	public static final Icon RIGHT_ALTERNATE_ICON = new GIcon("icon.right.alt");

	public static final Icon SAVE_AS =
		ResourceManager.getImageIcon(new DotDotDotIcon(new GIcon("icon.saveas")));

	public static final Icon MAKE_SELECTION_ICON = new GIcon("icon.makeselection");

	// Not necessarily re-usable, but this is needed for the help system; these should 
	// probably be moved to the client that uses them, while updating the
	// help system to use them there.
	public static final Icon ARROW_DOWN_RIGHT_ICON =
		ResourceManager.getImageIcon(new RotateIcon(new GIcon("icon.arrow.up.right"), 90));
	public static final Icon ARROW_UP_LEFT_ICON =
		ResourceManager.getImageIcon(new RotateIcon(new GIcon("icon.arrow.up.right"), 275));
	public static final Icon FILTER_NOT_ACCEPTED_ICON =
		ResourceManager.getImageIcon(new MultiIcon(new GIcon("icon.flag"),
			new TranslateIcon(ResourceManager.loadImage("icon.notallowed", 10, 10), 6, 6)));
	public static final Icon APPLY_BLOCKED_MATCH_ICON =
		ResourceManager.getImageIcon(new MultiIcon(new GIcon("icon.lock"),
			new TranslateIcon(ResourceManager.loadImage("icon.checkmark.green", 12, 12), 4, 0)));

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

		GIcon icon = getIconByFieldName(fieldName);
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

	private static GIcon getIconByFieldName(String fieldName) {

		try {
			Field field = Icons.class.getField(fieldName);
			Object object = field.get(Icons.class);
			GIcon icon = (GIcon) object;
			return icon;
		}
		catch (Exception e) {
			Msg.debug(Icons.class,
				"No icon named '" + fieldName + "' in class " + Icons.class.getName());
			return null;
		}
	}

	private static URL getUrlFromIcon(GIcon icon) {
		if (icon == null) {
			return null;
		}

		URL url = icon.getUrl();
		if (url != null) {
			return url;
		}
		Msg.debug(Icons.class, "Unable to get URL for icon");
		return null;
	}

	// Creates a 16x16 icon with a scaled base icon and puts 3 dots below it.
	private static class DotDotDotIcon implements Icon {
		private Icon base;

		public DotDotDotIcon(Icon base) {
			this.base = ResourceManager.getScaledIcon(base, 12, 12);
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			base.paintIcon(c, g, x, y);
			g.setColor(new Color(50, 50, 50));
			g.fillRect(x + 6, y + 14, 2, 2);
			g.fillRect(x + 9, y + 14, 2, 2);
			g.fillRect(x + 12, y + 14, 2, 2);

		}

		@Override
		public int getIconWidth() {
			return 16;
		}

		@Override
		public int getIconHeight() {
			return 16;
		}

	}

	private Icons() {
		// utility class
	}
}
