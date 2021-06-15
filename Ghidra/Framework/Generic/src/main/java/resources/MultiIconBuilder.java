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
import java.awt.font.FontRenderContext;
import java.awt.font.TextLayout;
import java.awt.image.BufferedImage;
import java.util.Objects;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.icons.TranslateIcon;

/**
 * A builder to allow for easier creation of an icon that is composed of a base icon, with 
 * other icons overlaid.  The {@link #build()} method returns an {@link ImageIcon}, as this
 * allows Java's buttons to automatically create disabled icons correctly.
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
	 * Adds the specified icon as an overlay to the base icon, possibly scaled according
	 * to the specified width and height, in the specified quadrant corner.
	 * 
	 * @param icon the icon to overlay
	 * @param w width of the overlaid icon
	 * @param h height of the overlaid icon
	 * @param quandrant corner to place the overlay on
	 * @return this builder (for chaining)
	 */
	public MultiIconBuilder addIcon(Icon icon, int w, int h, QUADRANT quandrant) {
		ImageIcon scaled = ResourceManager.getScaledIcon(icon, w, h);

		int x = (multiIcon.getIconWidth() - scaled.getIconWidth()) * quandrant.x;
		int y = (multiIcon.getIconHeight() - scaled.getIconHeight()) * quandrant.y;

		TranslateIcon txIcon = new TranslateIcon(scaled, x, y);
		multiIcon.addIcon(txIcon);
		return this;

	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-right
	 * 
	 * @param icon the icon
	 * @return this builder
	 */
	public MultiIconBuilder addLowerRightIcon(Icon icon) {
		return addIcon(icon, icon.getIconWidth(), icon.getIconHeight(), QUADRANT.LR);
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
		return addIcon(icon, w, h, QUADRANT.LR);
	}

	/**
	 * Adds the given icon as an overlay to the base icon, to the lower-left
	 * 
	 * @param icon the icon
	 * @return this builder
	 */
	public MultiIconBuilder addLowerLeftIcon(Icon icon) {
		return addIcon(icon, icon.getIconWidth(), icon.getIconHeight(), QUADRANT.LL);
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
		return addIcon(icon, w, h, QUADRANT.LL);
	}

	/**
	 * Add text overlaid on the base icon, aligned to the specified quadrant.
	 * 
	 * @param text Text string to write onto the icon.  Probably can only fit a letter or two
	 * @param font The font to use to render the text.  You know the size of the base icon, so
	 * you should be able to figure out the size of the font to use for the text
	 * @param color The color to use when rendering the text
	 * @param quandrant The {@link QUADRANT} to align the text to different parts of the icon
	 * @return this builder (for chaining)
	 */
	public MultiIconBuilder addText(String text, Font font, Color color, QUADRANT quandrant) {

		FontRenderContext frc = new FontRenderContext(null, true, true);
		TextLayout tl = new TextLayout(text, font, frc);

		BufferedImage bi = new BufferedImage((int) Math.ceil(tl.getAdvance()),
			(int) Math.ceil(tl.getAscent() + tl.getDescent()), BufferedImage.TYPE_INT_ARGB);

		Graphics2D g2d = (Graphics2D) bi.getGraphics();
		g2d.setFont(font);
		g2d.setColor(color);
		tl.draw(g2d, 0, tl.getAscent());
		g2d.dispose();

		return addIcon(new ImageIcon(bi), bi.getWidth(), bi.getHeight(), quandrant);
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
