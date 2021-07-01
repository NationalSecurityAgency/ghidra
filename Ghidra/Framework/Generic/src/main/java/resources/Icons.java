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
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import ghidra.util.Msg;
import resources.icons.RotateIcon;
import resources.icons.TranslateIcon;

/**
 * A class to get generic icons for standard actions.  All methods in this class return an 
 * icon that is 16x16 unless the method name ends in another size.'
 */
public class Icons {

	public static final ImageIcon EMPTY_ICON = get("images/EmptyIcon16.gif");

	public static final ImageIcon HELP_ICON = get("images/help-browser.png");

	public static final ImageIcon ADD_ICON = get("images/Plus2.png");

	public static final ImageIcon COLLAPSE_ALL_ICON = get("images/collapse_all.png");
	public static final ImageIcon EXPAND_ALL_ICON = get("images/expand_all.png");

	public static final ImageIcon CONFIGURE_FILTER_ICON = get("images/exec.png");
	public static final ImageIcon DELETE_ICON = get("images/error.png");
	public static final ImageIcon ERROR_ICON = get("images/emblem-important.png");

	public static final ImageIcon NAVIGATE_ON_INCOMING_EVENT_ICON = get("images/locationIn.gif");
	public static final ImageIcon NAVIGATE_ON_OUTGOING_EVENT_ICON = get("images/locationOut.gif");

	public static final ImageIcon NOT_ALLOWED_ICON = get("images/no.png");
	public static final ImageIcon OPEN_FOLDER_ICON = get("images/openSmallFolder.png");
	public static final ImageIcon REFRESH_ICON = get("images/reload3.png");

	public static final ImageIcon SORT_ASCENDING_ICON = get("images/sortascending.png");
	public static final ImageIcon SORT_DESCENDING_ICON = get("images/sortdescending.png");

	public static final ImageIcon STOP_ICON = get("images/process-stop.png");
	public static final ImageIcon STRONG_WARNING_ICON = get("images/software-update-urgent.png");

	public static final ImageIcon LEFT_ICON = get("images/left.png");
	public static final ImageIcon RIGHT_ICON = get("images/right.png");

	/** An version of the LEFT_ICON with a different color */
	public static final ImageIcon LEFT_ALTERNATE_ICON = get("images/left.alternate.png");

	/** An version of the RIGHT_ICON with a different color */
	public static final ImageIcon RIGHT_ALTERNATE_ICON = get("images/right.alternate.png");

	public static final ImageIcon SAVE_AS =
		ResourceManager.getImageIcon(new DotDotDotIcon(get("images/Disk.png")));

	public static final ImageIcon MAKE_SELECTION_ICON = get("images/text_align_justify.png");

	// Not necessarily re-usable, but this is needed for the help system; these should 
	// probably be moved to the client that uses them, while updating the
	// help system to use them there.
	public static final ImageIcon ARROW_DOWN_RIGHT_ICON =
		ResourceManager.getImageIcon(new RotateIcon(get("images/viewmagfit.png"), 90));
	public static final ImageIcon ARROW_UP_LEFT_ICON =
		ResourceManager.getImageIcon(new RotateIcon(get("images/viewmagfit.png"), 275));
	public static final ImageIcon FILTER_NOT_ACCEPTED_ICON =
		ResourceManager.getImageIcon(new MultiIcon(get("images/flag.png"), new TranslateIcon(
			ResourceManager.loadImage("images/dialog-cancel.png", 10, 10), 6, 6)));
	public static final ImageIcon APPLY_BLOCKED_MATCH_ICON =
		ResourceManager.getImageIcon(new MultiIcon(get("images/kgpg.png"), new TranslateIcon(
			ResourceManager.loadImage("images/checkmark_green.gif", 12, 12), 4, 0)));

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

		ImageIcon icon = getIconByFieldName(fieldName);
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
	 * Gets the icon for the given icon path and scale it to the specifed width and height.
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

	private static ImageIcon getIconByFieldName(String fieldName) {

		try {
			Field field = Icons.class.getField(fieldName);
			ImageIcon icon = (ImageIcon) field.get(Icons.class);
			return icon;
		}
		catch (Exception e) {
			Msg.debug(Icons.class,
				"No icon named '" + fieldName + "' in class " + Icons.class.getName());
			return null;
		}
	}

	private static URL getUrlFromIcon(ImageIcon icon) {
		if (icon == null) {
			return null;
		}

		// Note: we embed the icon's URL in its description
		String description = icon.getDescription();
		if (description == null) {
			Msg.debug(Icons.class, "Unable to get URL for icon - icon description is missing");
			return null;
		}

		try {
			URL url = new URL(description);
			return url;
		}
		catch (MalformedURLException e) {
			Msg.trace(Icons.class, "Unable to get URL for icon: " + description);
			return null;
		}

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
