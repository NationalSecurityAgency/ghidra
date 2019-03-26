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
package ghidra.app.nav;

import java.awt.Color;
import java.awt.Point;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.OvalColorIcon;
import resources.icons.TranslateIcon;

public class NavigatableIconFactory {

	private static final ImageIcon SNAPSHOT_ICON =
		ResourceManager.loadImage("images/camera-photo.png");

	public static ImageIcon createSnapshotOverlayIcon(Icon primaryIcon) {
		MultiIcon newOuterIcon = new MultiIcon(primaryIcon);

		Icon scaledIcon = ResourceManager.getScaledIcon(SNAPSHOT_ICON, 8, 8, 0);
		ImageIcon highlightIcon = getHighlightIcon(scaledIcon);
		MultiIcon highlightMultiIcon = new MultiIcon(highlightIcon);
		Point centerPoint = getCenteredIconOffset(highlightIcon, scaledIcon);
		highlightMultiIcon.addIcon(new TranslateIcon(scaledIcon, centerPoint.x, centerPoint.y));

		Point lowerRightPoint = getLowerRightIconOffset(primaryIcon, highlightMultiIcon);
		newOuterIcon.addIcon(
			new TranslateIcon(highlightMultiIcon, lowerRightPoint.x + 2, lowerRightPoint.y + 2));

		return ResourceManager.getImageIcon(newOuterIcon);
	}

	private static ImageIcon getHighlightIcon(Icon primaryIcon) {
		int primaryWidth = primaryIcon.getIconWidth();
		int primaryHeight = primaryIcon.getIconHeight();
		Color color = new Color(255, 255, 0, 255);
		return ResourceManager.getImageIcon(
			new OvalColorIcon(color, primaryWidth + 4, primaryHeight + 4));
	}

	private static Point getCenteredIconOffset(Icon primaryIcon, Icon overlayIcon) {
		int primaryWidth = primaryIcon.getIconWidth();
		int primaryHeight = primaryIcon.getIconHeight();

		int overlayWidth = overlayIcon.getIconWidth();
		int overlayHeight = overlayIcon.getIconHeight();

		int offsetX = (primaryWidth - overlayWidth) >> 1;
		int offsetY = (primaryHeight - overlayHeight) >> 1;

		return new Point(offsetX, offsetY);
	}

	private static Point getLowerRightIconOffset(Icon primaryIcon, Icon overlayIcon) {
		int primaryWidth = primaryIcon.getIconWidth();
		int primaryHeight = primaryIcon.getIconHeight();

		int overlayWidth = overlayIcon.getIconWidth();
		int overlayHeight = overlayIcon.getIconHeight();

		return new Point(primaryWidth - overlayWidth, primaryHeight - overlayHeight);
	}
}
