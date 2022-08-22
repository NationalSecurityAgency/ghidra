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
import java.awt.image.ImageObserver;

import javax.accessibility.AccessibleContext;
import javax.swing.ImageIcon;

import resources.ResourceManager;

/**
 * <code>LazyImageIcon</code> provides the ability to instantiate 
 * an ImageIcon with delayed loading.  In addition to delayed loading
 * it has the added benefit of allowing the use of static initialization
 * of ImageIcons without starting the Swing thread which can cause
 * problems when running headless.
 */
public abstract class LazyImageIcon extends ImageIcon implements FileBasedIcon {

	private boolean loaded;

	protected LazyImageIcon(String name) {
		setDescription(name);
	}

	private synchronized void init() {
		if (!loaded) {
			loaded = true;
			ImageIcon imageIcon = createImageIcon();
			if (imageIcon == null) {
				imageIcon = getDefaultIcon();
			}
			super.setImage(imageIcon.getImage());
			super.setDescription(getDescription());
		}
	}

	protected abstract ImageIcon createImageIcon();

	@Override
	public String getFilename() {
		return getDescription();
	}

	@Override
	public Image getImage() {
		init();
		return super.getImage();
	}

	@Override
	public AccessibleContext getAccessibleContext() {
		init();
		return super.getAccessibleContext();
	}

	@Override
	public String getDescription() {
		init();
		return super.getDescription();
	}

	@Override
	public int getIconHeight() {
		init();
		return super.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		init();
		return super.getIconWidth();
	}

	@Override
	public int getImageLoadStatus() {
		init();
		return super.getImageLoadStatus();
	}

	@Override
	public ImageObserver getImageObserver() {
		init();
		return super.getImageObserver();
	}

	@Override
	public synchronized void paintIcon(Component c, Graphics g, int x, int y) {
		init();
		super.paintIcon(c, g, x, y);
	}

	@Override
	public void setDescription(String description) {
		super.setDescription(description);
	}

	@Override
	public void setImage(Image image) {
		init();
		super.setImage(image);
	}

	@Override
	public String toString() {
		init();
		return super.toString();
	}

	private ImageIcon getDefaultIcon() {
		ImageIcon defaultIcon = ResourceManager.getDefaultIcon();
		if (this == defaultIcon) {
			// this can happen under just the right conditions when loading the default 
			// icon's bytes fails (probably due to disk or network issues)
			throw new IllegalStateException("Unexpected failure loading the default icon!");
		}
		return defaultIcon; // some sort of initialization has failed
	}
}
