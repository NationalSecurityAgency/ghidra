/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.menu;

import java.awt.*;
import java.awt.image.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.ResourceManager;


class InvertableImageIcon implements Icon {
	private ImageIcon icon;
	private ImageIcon originalIcon;
	private ImageIcon invertedIcon;

	public InvertableImageIcon(ImageIcon imageIcon) {
		this.originalIcon = imageIcon;
		icon = imageIcon;
	}

	private Image createInvertedImage (Image i) {
 		RGBImageFilter filter = new RGBImageFilter() {
			@Override
			public int filterRGB(int x, int y, int rgb) {
				if ((rgb & 0xff000000) == 0xff000000) {
					rgb = (~rgb) | 0xff000000;
				}
				return rgb;
			}
		};
 		ImageProducer prod = new FilteredImageSource(i.getSource(), filter);
 		return Toolkit.getDefaultToolkit().createImage(prod);
 	}

	public void setInverted(boolean inverted) {
		if (invertedIcon == null) {
			Image image = originalIcon.getImage();
			Image invertedImage = createInvertedImage(image);	
			invertedIcon = ResourceManager.getImageIconFromImage(originalIcon.getDescription(), invertedImage);
		}
		icon = inverted ? invertedIcon : originalIcon;
	}
	public boolean isInverted() {
		return icon == originalIcon;
	}
	/**
	 * @see javax.swing.Icon#getIconHeight()
	 */
	public int getIconHeight() {
		return icon.getIconHeight();
	}

	/**
	 * @see javax.swing.Icon#getIconWidth()
	 */
	public int getIconWidth() {
		return icon.getIconWidth();
	}

	/**
	 * @see javax.swing.Icon#paintIcon(java.awt.Component, java.awt.Graphics, int, int)
	 */
	public void paintIcon(Component c, Graphics g, int x, int y) {
		icon.paintIcon(c, g, x, y);
	}

 
}
