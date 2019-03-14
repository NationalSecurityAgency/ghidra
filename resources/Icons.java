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
import java.net.MalformedURLException;
import java.net.URL;

import javax.swing.ImageIcon;

import ghidra.util.Msg;

/**
 * A class to get generic icons for standard actions.  All methods in this class return an 
 * icon that is 16x16 unless the method name ends in another size.'
 */
public class Icons {

	public static final ImageIcon ADD_ICON = ResourceManager.loadImage("images/Plus2.png");

	public static final ImageIcon COLLAPSE_ALL_ICON =
		ResourceManager.loadImage("images/collapse_all.png");
	public static final ImageIcon EXPAND_ALL_ICON =
		ResourceManager.loadImage("images/expand_all.png");

	public static final ImageIcon CONFIGURE_FILTER_ICON =
		ResourceManager.loadImage("images/exec.png");
	public static final ImageIcon DELETE_ICON = ResourceManager.loadImage("images/error.png");
	public static final ImageIcon ERROR_ICON =
		ResourceManager.loadImage("images/emblem-important.png");

	public static final ImageIcon NAVIGATE_ON_INCOMING_EVENT_ICON =
		ResourceManager.loadImage("images/locationIn.gif");
	public static final ImageIcon NAVIGATE_ON_OUTGOING_EVENT_ICON =
		ResourceManager.loadImage("images/locationOut.gif");

	public static final ImageIcon NOT_ALLOWED_ICON = ResourceManager.loadImage("images/no.png");
	public static final ImageIcon OPEN_FOLDER_ICON =
		ResourceManager.loadImage("images/openSmallFolder.png");
	public static final ImageIcon REFRESH_ICON = ResourceManager.loadImage("images/reload3.png");

	public static final ImageIcon SORT_ASCENDING_ICON =
		ResourceManager.loadImage("images/sortascending.png");
	public static final ImageIcon SORT_DESCENDING_ICON =
		ResourceManager.loadImage("images/sortdescending.png");

	public static final ImageIcon STOP_ICON = ResourceManager.loadImage("images/process-stop.png");
	public static final ImageIcon STRONG_WARNING_ICON =
		ResourceManager.loadImage("images/software-update-urgent.png");

	public static final ImageIcon LEFT_ICON = ResourceManager.loadImage("images/left.png");
	public static final ImageIcon RIGHT_ICON = ResourceManager.loadImage("images/right.png");

	/** An version of the LEFT_ICON with a different color */
	public static final ImageIcon LEFT_ALTERNATE_ICON =
		ResourceManager.loadImage("images/left.alternate.png");

	/** An version of the RIGHT_ICON with a different color */
	public static final ImageIcon RIGHT_ALTERNATE_ICON =
		ResourceManager.loadImage("images/right.alternate.png");

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
	 * Returns a URL for the given code snippet if it is a field reference on this class 
	 * 
	 * @param snippet the snippet of Java code that references a field of this class
	 * @return the URL; null if the snippet does not refer to a field of this class
	 */
	public static URL getUrlForIconsReference(String snippet) {

		String fieldName = getIconName(snippet);
		if (fieldName == null) {
			return null;
		}

		ImageIcon icon = getIconByFieldName(fieldName);
		URL url = getUrlFromIcon(icon);
		return url;
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
			Msg.debug(Icons.class, "Unable to get URL for icon: " + description, e);
			return null;
		}

	}

	private Icons() {
		// utility class
	}
}
