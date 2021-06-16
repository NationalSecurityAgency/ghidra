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

public class ScaleDisableImageIconWrapper extends ImageIconWrapper {
    /** 
	 * The inverse percentage of gray (higher percentage equals less gray) to apply to 
	 * the disabled image; higher is brighter
     * 
	 */

	int brightnessPercent;
    int width;
    int height;

    /**
	 * Construct wrapped disabled ImageIcon based upon specified baseIcon. 
	 * 16 width, 16 height will be applied.
	 * @param baseIcon enabled icon to be rendered as disabled
     * @param brightnessPercent a brightness level specified using a 
	 * value in the range of 0 thru 100.
	 */
	public ScaleDisableImageIconWrapper(Icon baseIcon, int brightnessPercent) {
		this(baseIcon, brightnessPercent, 16, 16); // default to half gray
	}

	/**
	 * Construct wrapped disabled ImageIcon based upon specified baseIcon. 
	 * A 50% brightness will be applied.
	 * @param baseIcon enabled icon to be rendered as disabled
	 */
	public ScaleDisableImageIconWrapper(Icon baseIcon) {
		this(baseIcon, 50, 16, 16); // default to half gray
	}

	/**
	 * Construct wrapped disabled ImageIcon based upon specified baseIcon
	 * using the specified brightness level
	 * @param baseIcon
	 * @param brightnessPercent a brightness level specified using a 
	 * value in the range of 0 thru 100.
     * @param width new icon width
     * @param height new icon height
	 */
	public ScaleDisableImageIconWrapper(Icon baseIcon, int brightnessPercent, int width, int height) {
		super(baseIcon);
		this.brightnessPercent = brightnessPercent;
        this.width = width;
        this.height = height;
	}

	@Override
	protected ImageIcon createImageIcon() {
		ImageIcon baseIcon = super.createImageIcon();
		Image scaleDisabledImage =
			ImageUtils.createScaleDisablImage(baseIcon.getImage(), width, height, brightnessPercent);
		return new ImageIcon(scaleDisabledImage, getImageName());
	}

}