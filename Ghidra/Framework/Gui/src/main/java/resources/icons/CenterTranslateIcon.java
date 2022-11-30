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
package resources.icons;

import javax.swing.Icon;

/**
 * An icon that will update it's x,y offset to be centered over another, presumably larger
 * icon.
 */
public class CenterTranslateIcon extends TranslateIcon {

	/**
	 * Constructor
	 * 
	 * @param icon the icon to center
	 * @param centerOverSize the size of the area over which this icon is be centered.  
	 *        <p>
	 *        Note:  this constructor assumes the area is a square. If not, add another
	 *        constructor to this class that takes a width and height for the area
	 */
	public CenterTranslateIcon(Icon icon, int centerOverSize) {
		super(icon, getCenterX(icon, centerOverSize), getCenterY(icon, centerOverSize));
	}

	private static int getCenterY(Icon icon, int baseIconSize) {
		return (baseIconSize / 2) - (icon.getIconHeight() / 2);
	}

	private static int getCenterX(Icon icon, int baseIconSize) {
		return (baseIconSize / 2) - (icon.getIconWidth() / 2);
	}

}
