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

import java.awt.*;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.util.image.ImageUtils;

public class ScaledImageIconWrapper extends ImageIconWrapper {

	private int width;
	private int height;
	private int hints;

	/**
	 * Construct wrapped scaled ImageIcon based upon specified
	 * baseIcon and desired size.  The rendering hints of 
	 * {@link Image#SCALE_AREA_AVERAGING} will be applied.
	 * @param baseIcon base icon
	 * @param width new icon width
	 * @param height new icon height
	 */
	public ScaledImageIconWrapper(Icon baseIcon, int width, int height) {
		this(baseIcon, width, height, Image.SCALE_AREA_AVERAGING);
	}

	/**
	 * Construct wrapped scaled ImageIcon based upon specified
	 * baseIcon and desired size
	 * @param baseIcon base icon
	 * @param width new icon width
	 * @param height new icon height
	 * @param hints {@link RenderingHints} used by {@link Graphics2D} 
	 */
	public ScaledImageIconWrapper(Icon baseIcon, int width, int height, int hints) {
		super(baseIcon);
		this.width = width;
		this.height = height;
		this.hints = hints;
	}

	@Override
	protected ImageIcon createImageIcon() {
		ImageIcon baseIcon = super.createImageIcon();
		Image scaledImage = ImageUtils.createScaledImage(baseIcon.getImage(), width, height, hints);
		return new ImageIcon(scaledImage, getImageName());
	}
}
