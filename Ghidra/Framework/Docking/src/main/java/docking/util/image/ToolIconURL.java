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
package docking.util.image;

import java.awt.image.*;
import java.io.File;
import java.util.Hashtable;

import javax.swing.ImageIcon;

import generic.Images;
import resources.ResourceManager;

/**
 * Container class for an icon and its location. If the location is
 * not valid, then a default "bomb" icon is used as the icon.
 */
public class ToolIconURL implements Comparable<ToolIconURL> {

	/**
	 * The large icon size (height and width)
	 */
	public static final int LARGE_ICON_SIZE = 24;

	/**
	 * The medium icon size (height and width)
	 */
	public static final int MEDIUM_ICON_SIZE = 22;

	/**
	 * The small icon size (height and width)
	 */
	public static final int SMALL_ICON_SIZE = 16;

	private static final int MAX_IMAGE_LOAD_TIME = 5000;

	private String location;

	private ImageIcon baseIcon;
	private ImageIcon smallIcon;
	private ImageIcon largeIcon;
	private byte[] iconBytes;

	private boolean hasCheckedForAnimatedStatus;
	private boolean isAnimated;
	private int checkStatus;

	/**
	 * Constructor
	 * 
	 * @param location filename for the icon (relative or absolute)
	 */
	public ToolIconURL(String location) {
		if (location == null) {
			location = Images.BOMB;
		}
		this.location = location;

		loadIconFromLocation(location);
	}

	private void loadIconFromLocation(String iconLocation) {
		// is it absolute, or in resources by the given path?
		baseIcon = ResourceManager.loadImage(iconLocation);

		if (baseIcon == ResourceManager.getDefaultIcon()) {
			// ...must not be, look for it in our 'special' locations
			baseIcon = loadFromKnownImageResources(iconLocation);
		}
	}

	public ToolIconURL(String location, byte[] bytes) {
		this.location = location;
		this.iconBytes = bytes;

		File file = new File(location);
		baseIcon = ResourceManager.loadImage(file.getName(), bytes);
	}

	@Override
	public int compareTo(ToolIconURL that) {
		return location.compareToIgnoreCase(that.location);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((location == null) ? 0 : location.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ToolIconURL other = (ToolIconURL) obj;
		if (location == null) {
			if (other.location != null) {
				return false;
			}
		}
		else if (!location.equals(other.location)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return location;
	}

	private ImageIcon getSmallIcon(ImageIcon unscaledIcon) {
		if (unscaledIcon.getIconHeight() == SMALL_ICON_SIZE &&
			unscaledIcon.getIconHeight() == SMALL_ICON_SIZE) {
			return unscaledIcon;
		}

		// can we find this icon in the desired size on disk?
		ImageIcon image = findCompatibleImageForSize(location, SMALL_ICON_SIZE);
		if (image != null) {
			return image;
		}

		return ResourceManager.getScaledIcon(unscaledIcon, SMALL_ICON_SIZE,
			SMALL_ICON_SIZE);
	}

	private ImageIcon getLargeIcon(ImageIcon unscaledIcon) {
		if (unscaledIcon.getIconHeight() == LARGE_ICON_SIZE &&
			unscaledIcon.getIconHeight() == LARGE_ICON_SIZE) {
			return unscaledIcon;
		}

		// can we find this icon in the desired size on disk?
		ImageIcon image = findCompatibleImageForSize(location, LARGE_ICON_SIZE);
		if (image != null) {
			return image;
		}

		// ...try the medium size
		image = findCompatibleImageForSize(location, MEDIUM_ICON_SIZE);
		if (image != null) {
			return image;
		}

		// O.K., we will scale the icon.  However, if it is the default icon, we know we have 
		// a 'large' version of that.
		if (unscaledIcon == ResourceManager.getDefaultIcon()) {
			return ResourceManager.loadImage(Images.BIG_BOMB);
		}

		return ResourceManager.getScaledIcon(unscaledIcon, LARGE_ICON_SIZE,
			LARGE_ICON_SIZE);
	}

	private ImageIcon findCompatibleImageForSize(String imagePath, int desiredSize) {

		String name = imagePath;
		int dotIndex = name.lastIndexOf('.');
		if (dotIndex != -1) {
			name = name.substring(0, dotIndex);
		}

		name = stripSizeOffName(name);

		name += desiredSize;
		if (dotIndex != -1) {
			// add the dot back on
			name += location.substring(dotIndex);
		}

		ImageIcon image = getImageIcon(name);
		if (image != null) {
			return image;
		}
		return null;
	}

	private String stripSizeOffName(String name) {
		// try the last character...
		char character = name.charAt(name.length() - 1);
		if (!Character.isDigit(character)) {
			return name;
		}

		// try one more place from the end
		character = name.charAt(name.length() - 2);
		if (!Character.isDigit(character)) {
			// only the last char is a digit; strip it off
			return name.substring(0, name.length() - 1);
		}

		// just strip off the last two chars that are digits, if there are more, we don't support it
		return name.substring(0, name.length() - 2);
	}

	private ImageIcon getImageIcon(String name) {
		ImageIcon image = ResourceManager.loadImage(name);
		ImageIcon defaultIcon = ResourceManager.getDefaultIcon();
		if (image == defaultIcon) {
			if (!name.startsWith("images")) {
				return getImageIcon("images/" + name);
			}
			return null;
		}
		return image;
	}

	/**
	 * Returns true if the Icon is an animated image.
	 * <p>
	 * <b>WARNING: </b> This call may block the Swing thread for up to {@link #MAX_IMAGE_LOAD_TIME}
	 * milliseconds the first time it is called!
	 * @return true if animated
	 */
	public boolean isAnimated() {
		if (!hasCheckedForAnimatedStatus) {
			checkAnimated(baseIcon);
			hasCheckedForAnimatedStatus = true;
		}

		return isAnimated;
	}

	/**
	 * Return the location of this icon
	 * @return the location of this icon
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * Return the icon as {@link #SMALL_ICON_SIZE} pixel size.
	 * @return the icon
	 */
	public ImageIcon getSmallIcon() {
		if (smallIcon == null) {
			smallIcon = getSmallIcon(baseIcon);
		}

		return smallIcon;
	}

	/**
	 * Return the icon as {@link #LARGE_ICON_SIZE} pixel size.
	 * @return the icon
	 */
	public ImageIcon getIcon() {
		if (largeIcon == null) {
			largeIcon = getLargeIcon(baseIcon); // lazy load, since it forced initialization
		}

		return largeIcon;
	}

	/**
	 * Returns the icon bytes
	 * @return the bytes
	 */
	public byte[] getIconBytes() {
		return iconBytes;
	}

	/**
	 * Load the image as a resource, using the ResourceManager.
	 * @param name name of the icon
	 */
	private ImageIcon loadFromKnownImageResources(String name) {
		// first look in special location for tool icons
		String filename = "defaultTools/images/" + name;
		ImageIcon image = ResourceManager.loadImage(filename);

		// if we can't find the icon in the special tool icon location, then look in general images.
		if (image == ResourceManager.getDefaultIcon()) {
			filename = "images/" + name;
			image = ResourceManager.loadImage(filename);
		}
		return image;
	}

	private void checkAnimated(ImageIcon imgIcon) {
		if (imgIcon == null) {
			return;
		}

		setImageLoadingStatus(-1);

		ImageProducer ip = imgIcon.getImage().getSource();
		ImageConsumer ic = new ToolIconImageConsumer();

		ip.startProduction(ic);
		long waitTime = 0;
		long sleepTime = 50;
		try {
			// don't loop forever
			for (; !isImageLoadingComplete() && waitTime < MAX_IMAGE_LOAD_TIME; waitTime +=
				sleepTime) {
				Thread.sleep(sleepTime);
			}
		}
		catch (InterruptedException e) {
			// don't care--this will just report false for animated
		}
		ip.removeConsumer(ic);
		isAnimated = (checkStatus == ImageConsumer.SINGLEFRAMEDONE);
	}

	// synchronize access to 'checkStatus' so that the value does not become cached and there is
	// not odd call ordering problems
	private synchronized void setImageLoadingStatus(int status) {
		checkStatus = status;
	}

	// synchronize access to 'checkStatus' so that the value does not become cached and there is
	// not odd call ordering problems
	private synchronized boolean isImageLoadingComplete() {
		return (checkStatus >= 0);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ToolIconImageConsumer implements ImageConsumer {
		@Override
		public void imageComplete(int status) {
			setImageLoadingStatus(status);
		}

		@Override
		public void setHints(int hintflags) {
			// don't care
		}

		@Override
		public void setDimensions(int width, int height) {
			// don't care				
		}

		@Override
		public void setPixels(int x, int y, int w, int h, ColorModel model, byte[] pixels, int off,
				int scansize) {
			// don't care				
		}

		@Override
		public void setPixels(int x, int y, int w, int h, ColorModel model, int[] pixels, int off,
				int scansize) {
			// don't care				
		}

		@Override
		public void setColorModel(ColorModel model) {
			// don't care				
		}

		@Override
		public void setProperties(Hashtable<?, ?> props) {
			// don't care				
		}
	}
}
