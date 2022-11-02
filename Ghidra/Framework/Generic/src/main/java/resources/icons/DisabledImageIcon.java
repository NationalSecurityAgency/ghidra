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

import java.awt.Image;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.util.image.ImageUtils;

/**
 * {@link LazyImageIcon} that creates a disabled version of an icon
 */
public class DisabledImageIcon extends DerivedImageIcon {

	/** 
	 * The inverse percentage of gray (higher percentage equals less gray) to apply to 
	 * the disabled image; higher is brighter
	 */
	private int brightnessPercent;

	/**
	 * Construct wrapped disabled ImageIcon based upon specified baseIcon. 
	 * A 50% brightness will be applied.
	 * @param baseIcon enabled icon to be rendered as disabled
	 */
	public DisabledImageIcon(Icon baseIcon) {
		this(baseIcon, 50); // default to half gray
	}

	/**
	 * Construct wrapped disabled ImageIcon based upon specified baseIcon
	 * using the specified brightness level
	 * @param baseIcon the icon to create a disabled version of
	 * @param brightnessPercent a brightness level specified using a 
	 * value in the range of 0 thru 100.
	 */
	public DisabledImageIcon(Icon baseIcon, int brightnessPercent) {
		super(baseIcon);
		this.brightnessPercent = brightnessPercent;
	}

	@Override
	protected ImageIcon createImageIcon() {
		Image image = createImage();
		Image disabledImage = ImageUtils.createDisabledImage(image, brightnessPercent);
		return new ImageIcon(disabledImage, getFilename());
	}

}
