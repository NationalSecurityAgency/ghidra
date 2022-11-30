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
package resources.icons;

import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.image.BufferedImage;

import javax.swing.Icon;
import javax.swing.ImageIcon;

/**
 * {@link LazyImageIcon} that creates a reflected version of an icon. This creates a version of the
 * icon which has had either its x values reflected (left to right) or its y values reflected
 * (upside down)
 */
public class ReflectedIcon extends DerivedImageIcon {

	private boolean leftToRight;

	/**
	 * Construct a icon that is reflected either left to right or upside down.
	 * @param baseIcon base icon
	 * @param leftToRight true flips x values, false flips y values
	 */
	public ReflectedIcon(Icon baseIcon, boolean leftToRight) {
		super(baseIcon);
		this.leftToRight = leftToRight;
	}

	@Override
	protected ImageIcon createImageIcon() {
		Icon sourceIcon = getSourceIcon();
		Image image = createImage();
		int width = sourceIcon.getIconWidth();
		int height = sourceIcon.getIconHeight();

		BufferedImage flippedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics2D graphics = (Graphics2D) flippedImage.getGraphics();
		if (leftToRight) {
			graphics.drawImage(image, width, 0, -width, height, null);
		}
		else {
			graphics.drawImage(image, 0, height, width, -height, null);
		}
		graphics.dispose();
		return new ImageIcon(flippedImage, getFilename());
	}
}
