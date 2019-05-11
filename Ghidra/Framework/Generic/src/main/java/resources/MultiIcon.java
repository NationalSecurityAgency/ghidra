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
import java.util.ArrayList;
import java.util.Objects;

import javax.swing.Icon;

/**
 * Icon class for for displaying overlapping icons.  Icons are drawn in the order they
 * are added.
 */
public class MultiIcon implements Icon {

	private java.util.List<Icon> iconList;

	private boolean disabled;

	private boolean loaded;
	private int height;
	private int width;
	private String description;

	/**
	 * Constructs a new MultiIcon with an initial base icon that will always be drawn first.
	 * @param baseIcon the base icon that will always be drawn first.
	 */
	public MultiIcon(Icon baseIcon) {
		this(baseIcon, false);
	}

	/**
	 * Constructs a new MultiIcon with an initial base icon that will always be drawn first.
	 * @param baseIcon the base icon that will always be drawn first.
	 */
	public MultiIcon(Icon baseIcon, boolean disabled) {
		Objects.requireNonNull(baseIcon, "baseIcon may not be null");
		this.disabled = disabled;
		iconList = new ArrayList<>(4);
		addIcon(baseIcon);
	}

	/**
	 * Construct a new MultiIcon with the provided base image and subsequent images
	 * @param baseIcon base image always drawn first
	 * @param icons images drawn atop the base
	 */
	public MultiIcon(Icon baseIcon, Icon... icons) {
		this(baseIcon, false);
		for (Icon icon : icons) {
			iconList.add(icon);
		}
	}

	/**
	 * Construct a new MultiIcon with a predetermined size
	 * @param baseIcon Primary icon that is always drawn first
	 * @param disabled flag to draw this icon in a disabled state
	 * @param width horizontal dimension of this icon
	 * @param height vertical dimension of this icon
	 */
	public MultiIcon(Icon baseIcon, boolean disabled, int width, int height) {
		iconList = new ArrayList<>(4);
		iconList.add(baseIcon);
		this.width = width;
		this.height = height;
		this.loaded = true;
		this.disabled = disabled;
	}

	/**
	 * Adds an icon that is to be drawn on top of the base icon and any other icons that
	 * have been added.
	 * @param icon the icon to be added.
	 */
	public void addIcon(Icon icon) {
		if (icon == null) {
			return;
		}
		iconList.add(icon);
	}

	private void init() {
		if (!loaded) {
			loaded = true;
			height = 0;
			width = 0;
			for (Icon icon : iconList) {
				height = Math.max(height, icon.getIconHeight());
				width = Math.max(width, icon.getIconWidth());
			}
		}
	}

	public String getDescription() {
		if (description == null) {
			description = iconList.get(0).toString();
		}
		return description;
	}

	/**
	 * @see javax.swing.Icon#getIconHeight()
	 */
	@Override
	public int getIconHeight() {
		init();
		return height;
	}

	/**
	 * @see javax.swing.Icon#getIconWidth()
	 */
	@Override
	public int getIconWidth() {
		init();
		return width;
	}

	/**
	 * @see javax.swing.Icon#paintIcon(java.awt.Component, java.awt.Graphics, int, int)
	 */
	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		init();
		for (int i = 0; i < iconList.size(); i++) {
			Icon icon = iconList.get(i);
			icon.paintIcon(c, g, x, y);
		}

		if (disabled) {
			// Alpha blend to background
			Color bgColor = c.getBackground();
			g.setColor(new Color(bgColor.getRed(), bgColor.getGreen(), bgColor.getBlue(), 128));
			g.fillRect(x, y, width, height);
		}
	}

	/**
	 * Return array of Icons that were added to this MultIcon.
	 */
	public Icon[] getIcons() {
		return iconList.toArray(new Icon[iconList.size()]);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[" + getIconNames() + "]";
	}

	private String getIconNames() {
		StringBuffer buffy = new StringBuffer();
		for (Icon icon : iconList) {
			if (buffy.length() > 0) {
				buffy.append(", ");
			}
			buffy.append(ResourceManager.getIconName(icon));
		}

		return buffy.toString();
	}
}
