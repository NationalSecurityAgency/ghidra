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

import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.util.Objects;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.theme.GIcon;
import generic.util.image.ImageUtils;
import resources.ResourceManager;

/**
 * {@link LazyImageIcon} that is created from an {@link Icon} or an {@link Image}
 */
public class DerivedImageIcon extends LazyImageIcon {
	private Icon sourceIcon;
	private Image sourceImage;
	private Icon cachedDelegate;

	/**
	 * Constructor for deriving from an icon
	 * @param icon the source icon
	 */
	public DerivedImageIcon(Icon icon) {
		super(ResourceManager.getIconName(icon));
		this.sourceIcon = Objects.requireNonNull(icon);
	}

	/**
	 * Constructor for deriving from an image
	 * @param name the name of the image
	 * @param image the source image
	 */
	public DerivedImageIcon(String name, Image image) {
		super(name);
		this.sourceImage = Objects.requireNonNull(image);
	}

	public Icon getSourceIcon() {
		return sourceIcon;
	}

	protected boolean sourceIconChanged() {
		if (sourceIcon instanceof GIcon gIcon) {
			if (cachedDelegate != gIcon.getDelegate()) {
				cachedDelegate = gIcon.getDelegate();
				return true;
			}
		}
		return false;
	}

	protected ImageIcon createImageIcon() {
		Image image = createImage();
		String imageName = getFilename();
		if (!ImageUtils.waitForImage(imageName, image)) {
			return null;
		}
		return new ImageIcon(image, imageName);
	}

	protected Image createImage() {
		if (sourceImage != null) {
			return sourceImage;
		}

		// if sourceImage is null, then sourceIcon can't be null
		if (sourceIcon instanceof ImageIcon) {
			return ((ImageIcon) sourceIcon).getImage();
		}
		BufferedImage bufferedImage = new BufferedImage(sourceIcon.getIconWidth(),
			sourceIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = bufferedImage.getGraphics();
		sourceIcon.paintIcon(null, graphics, 0, 0);
		graphics.dispose();
		return bufferedImage;
	}
}
