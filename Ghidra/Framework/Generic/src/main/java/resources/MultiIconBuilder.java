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

import java.util.Objects;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.icons.TranslateIcon;

/**
 * A builder to allow for easier creation of an icon that is composed of a base icon, with 
 * other icons overlayed.  The {@link #build()} method returns an {@link ImageIcon}, as this
 * allows Java's buttons to create analogue disabled icons correctly.
 * 
 * <P>Note: this class is a work-in-progress.  Add more methods for locating overlays as needed. 
 */
public class MultiIconBuilder {

	private MultiIcon multiIcon;
	private String description;

	public MultiIconBuilder(Icon baseIcon) {
		this.multiIcon = new MultiIcon(Objects.requireNonNull(baseIcon));
	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-right
	 * 
	 * @param icon the icon
	 * @return this builder
	 */
	public MultiIconBuilder addLowerRightIcon(Icon icon) {
		return addLowerRightIcon(icon, icon.getIconWidth(), icon.getIconHeight());
	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-right,
	 * scaled to the given width and height
	 * 
	 * @param icon the icon
	 * @param w the desired width
	 * @param h the desired height
	 * @return this builder
	 */
	public MultiIconBuilder addLowerRightIcon(Icon icon, int w, int h) {

		ImageIcon scaled = ResourceManager.getScaledIcon(icon, w, h);

		int x = multiIcon.getIconWidth() - scaled.getIconWidth();
		int y = multiIcon.getIconHeight() - scaled.getIconHeight();
		TranslateIcon txIcon = new TranslateIcon(scaled, x, y);
		multiIcon.addIcon(txIcon);
		return this;
	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-left
	 * 
	 * @param icon the icon
	 * @return this builder
	 */
	public MultiIconBuilder addLowerLeftIcon(Icon icon) {
		return addLowerLeftIcon(icon, icon.getIconWidth(), icon.getIconHeight());
	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-left,
	 * scaled to the given width and height
	 * 
	 * @param icon the icon
	 * @param w the desired width
	 * @param h the desired height
	 * @return this builder
	 */
	public MultiIconBuilder addLowerLeftIcon(Icon icon, int w, int h) {

		ImageIcon scaled = ResourceManager.getScaledIcon(icon, w, h);

		int x = 0;
		int y = multiIcon.getIconHeight() - scaled.getIconHeight();
		TranslateIcon txIcon = new TranslateIcon(scaled, x, y);
		multiIcon.addIcon(txIcon);
		return this;
	}

	/**
	 * Sets a description for the icon being built.  This is useful for debugging.
	 * 
	 * @param description the description
	 * @return this builder
	 */
	public MultiIconBuilder setDescription(String description) {
		this.description = description;
		return this;
	}

	public ImageIcon build() {
		ImageIcon imageIcon = ResourceManager.getImageIcon(multiIcon);
		imageIcon.setDescription(getDescription());
		return imageIcon;
	}

	private String getDescription() {
		if (description != null) {
			return description;
		}
		return multiIcon.toString();
	}
}
