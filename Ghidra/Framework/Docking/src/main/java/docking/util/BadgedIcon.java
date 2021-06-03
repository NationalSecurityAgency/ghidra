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
package docking.util;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.EmptyIcon;
import resources.icons.ScaledImageIconWrapper;

/**
 * An icon that allows sub-icons to be added at key perimeter locations. Each position can 
 * be manipulated independently, adding and removing icons as desired. Additionally, 
 * each position can be toggled enabled or disabled, or visible or invisible.
 */
public class BadgedIcon implements Icon {

	/*
	 * The top-edge horizontal positions move up 20% from origin
	 * The middle horizontal positions are at origin+30%
	 * The bottom-edge horizontal positions are at origin+60%
	 * 
	 * The left-edge vertical positions move left 20% from origin
	 * The middle vertical positions are at origin+30%
	 * The right-edge vertical positions are at origin+60%
	 *  
	 */
	public enum BadgePosition {
		TopLeft(-.2, -.2),
		TopMiddle(.3, -.2),
		TopRight(.6, -.2),

		LeftMiddle(-.2, .3),
		Center(.3, .3),
		RightMiddle(.6, .3),

		BottomLeft(-.2, .6),
		BottomMiddle(.3, .6),
		BottomRight(.6, .6);

		private final double horizontalDisplacementFactor;
		private final double verticalDisplacementFactor;

		private BadgePosition(double hdf, double vdf) {
			horizontalDisplacementFactor = hdf;
			verticalDisplacementFactor = vdf;
		}

		public double getHorizontalDisplacementFactor() {
			return horizontalDisplacementFactor;
		}

		public double getVerticalDisplacementFactor() {
			return verticalDisplacementFactor;
		}

	}

	private Map<BadgePosition, MultiIcon> badgeMap = new EnumMap<>(BadgePosition.class);
	private Map<BadgePosition, Boolean> badgeEnablement = new EnumMap<>(BadgePosition.class);
	private Map<BadgePosition, Boolean> badgeVisibility = new EnumMap<>(BadgePosition.class);

	private static double BADGE_HSCALE_FACTOR = .75;
	private static double BADGE_VSCALE_FACTOR = .75;

	// if the icon hasn't changed, this will help in painting...
	private Icon cachedThis = null;

	private Icon base;

	private int height;
	private int width;
	private boolean enabled;

	public BadgedIcon(Icon baseIcon) {
		this(baseIcon, true);
	}

	public BadgedIcon(Icon baseIcon, boolean enabled) {
		this(baseIcon, enabled, baseIcon.getIconWidth(), baseIcon.getIconHeight());
	}

	public BadgedIcon(Icon baseIcon, boolean enabled, int width, int height) {

		Objects.requireNonNull(baseIcon, "Base Icon must not be null");

		this.base = baseIcon;
		this.width = width;
		this.height = height;
		this.enabled = enabled;

		initDefaultBadges();

		cachedThis = null;
	}

	private static MultiIcon getEmptyIcon(int width, int height, boolean enabled) {
		return new MultiIcon(new EmptyIcon(width, height), !enabled);
	}

	private void initDefaultBadges() {
		for (BadgePosition pos : BadgePosition.values()) {

			badgeMap.put(pos, getEmptyIcon(width, height, enabled));
			badgeEnablement.put(pos, true);
			badgeVisibility.put(pos, true);
		}
	}

	/**
	 * Add an icon at the specified location
	 * @param badge The icon
	 * @param position Where to place the image
	 * @return a reference to this object
	 */
	public BadgedIcon addBadge(Icon badge, BadgePosition position) {

		badgeMap.get(position).addIcon(badge);

		height = Math.max(height, badge.getIconHeight());
		width = Math.max(width, badge.getIconWidth());

		cachedThis = null;

		return this;
	}

	public BadgedIcon addScaledBadge(Icon icon, int newWidth, int newHeight,
			BadgePosition position) {

		Icon badge = ResourceManager.getScaledIcon(icon, width, height);

		badgeMap.get(position).addIcon(badge);

		height = Math.max(height, badge.getIconHeight());
		width = Math.max(width, badge.getIconWidth());

		cachedThis = null;

		return this;
	}

	/**
	 * Replace the existing icon with the provided icon at the specified location
	 * @param badge The icon
	 * @param position Where to place the image
	 * @return a reference to this object
	 */
	public BadgedIcon setBadge(Icon badge, BadgePosition position) {
		MultiIcon multi = null;
		if (badge == null) {
			badge = getEmptyIcon(width, height, enabled);
		}
		multi = new MultiIcon(badge, enabled, width, height);
		badgeMap.put(position, multi);

		cachedThis = null;

		return this;
	}

	/**
	 * Remove the badge from the specified location
	 * @param position Where to place the image
	 * @return a reference to this object
	 */
	public BadgedIcon removeBadge(BadgePosition position) {
		setBadge(null, position);
		return this;
	}

	/**
	 * Set the enablement of the badge at the specified location
	 * @param position Which icon to modify
	 * @param enabled True if the image should be shown 'enabled', false otherwise
	 * @see BadgedIcon#isBadgeEnabled(BadgePosition)
	 */
	public void setBadgeEnabled(BadgePosition position, boolean enabled) {
		if (isBadgeEnabled(position) == enabled) {
			return;
		}
		badgeEnablement.put(position, enabled);
		cachedThis = null;
	}

	/**
	 * Get the enablement status of the badge at the specified location
	 * @param position Which icon to enquire about
	 * @return True if the badge is enabled, false otherwise
	 * @see BadgedIcon#setBadgeEnabled(BadgePosition, boolean)
	 */
	public boolean isBadgeEnabled(BadgePosition position) {
		return badgeEnablement.get(position);
	}

	/**
	 * Set the visibility status of the badge at the specified location
	 * @param position Which icon to modify
	 * @param visible True if the badge should be visible, false otherwise
	 * @see #isBadgeVisible(BadgePosition)
	 */
	public void setBadgeVisisble(BadgePosition position, boolean visible) {
		if (isBadgeVisible(position) == visible) {
			return;
		}
		badgeVisibility.put(position, visible);

		cachedThis = null;
	}

	/**
	 * Get the visibility status of the badge at the specified location
	 * @param position Which icon to enquire about
	 * @return True if the badge is visible, false otherwise
	 * @see #setBadgeVisisble(BadgePosition, boolean)
	 */
	public boolean isBadgeVisible(BadgePosition position) {
		return badgeVisibility.get(position);
	}

	/**
	 * @see javax.swing.Icon#getIconHeight()
	 */
	@Override
	public int getIconHeight() {
		return height;
	}

	/**
	 * @see javax.swing.Icon#getIconWidth()
	 */
	@Override
	public int getIconWidth() {
		return width;
	}

	/** 
	 * Determine the overall enablement appearance state.
	 * @return true if the if the entire icon is rendered as 'enabled'; false otherwise.
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Set the 'enabled' appearance of the entire icon.
	 * Preserves the underlying enablement state of badges, though the entire icon
	 * looks disabled if <code>setEnabled(true)</code> is called.
	 * @param enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Return array of Icons that were added to this BadgedIcon.
	 */
	public Icon[] getBadges(BadgePosition pos) {
		MultiIcon badge = badgeMap.get(pos);
		return badge.getIcons();
	}

	private Dimension getBadgeDimension() {
		return new Dimension((int) (width * BADGE_HSCALE_FACTOR),
			(int) (height * BADGE_VSCALE_FACTOR));
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {

		if (cachedThis != null) {
			cachedThis.paintIcon(c, g, x, y);
		}
		else {
			Dimension badgeSize = getBadgeDimension();
			doPaintIcon(c, g, x, y, badgeSize);
		}

		if (!enabled) {
			// Alpha blend to background
			Color bgColor = c.getBackground();
			g.setColor(new Color(bgColor.getRed(), bgColor.getGreen(), bgColor.getBlue(), 128));
			g.fillRect(x, y, width, height);
		}

	}

	private void doPaintIcon(Component c, Graphics g, int x, int y, Dimension badgeSize) {
		BufferedImage cached = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics gc = cached.getGraphics();

		base.paintIcon(c, gc, x, y);

		for (BadgePosition pos : BadgePosition.values()) {
			if (!isBadgeVisible(pos)) {
				continue;
			}

			MultiIcon icon = badgeMap.get(pos);

			Icon scaled = new ScaledImageIconWrapper(icon, badgeSize.width, badgeSize.height);

			Point badgePaintLoc = getBadgePaintLocation(pos, badgeSize);

			int badgeX = x + badgePaintLoc.x;
			int badgeY = y + badgePaintLoc.y;

			scaled.paintIcon(c, gc, badgeX, badgeY);

			if (!isBadgeEnabled(pos)) {
				// Alpha blend to background
				Color bgColor = c.getBackground();
				gc.setColor(
					new Color(bgColor.getRed(), bgColor.getGreen(), bgColor.getBlue(), 128));
				gc.fillRect(badgeX, badgeY, badgeSize.width, badgeSize.height);
			}
		}

		cachedThis = new ImageIcon(cached);

		cachedThis.paintIcon(c, g, x, y);
	}

	private static Point getBadgePaintLocation(BadgePosition pos, Dimension badgeSize) {

		double dx = pos.getHorizontalDisplacementFactor();
		double dy = pos.getVerticalDisplacementFactor();

		Point p = new Point((int) (dx * badgeSize.width), (int) (dy * badgeSize.height));

		return p;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[" + getIconNames() + "]";
	}

	private String getIconNames() {

		StringBuffer buffy = new StringBuffer();

		for (BadgePosition pos : BadgePosition.values()) {
			MultiIcon mi = badgeMap.get(pos);
			buffy.append(pos).append("[").append(mi.toString()).append("]");
			buffy.append(", ");
		}

		return buffy.toString();
	}

}
