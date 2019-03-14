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
import java.io.*;
import java.net.URL;

import javax.accessibility.AccessibleContext;
import javax.swing.ImageIcon;

import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * Wrap the ImageIcon so that the icon is not loaded upon construction; create the icon as needed.
 */
public class ImageIconWrapper extends ImageIcon implements FileBasedIcon {

	private ImageIcon icon;
	private Image image;
	private boolean loaded;

	private URL imageURL;
	private byte[] imageBytes;
	private final String imageName;

	public ImageIconWrapper(byte[] imageBytes, String imageName) {
		if (imageBytes == null) {
			throw new NullPointerException("Cannot create an ImageIconWrapper from a null URL");
		}
		if (imageBytes.length == 0) {
			throw new IllegalArgumentException("Cannot create an image from 0 bytes");
		}
		this.imageBytes = imageBytes;
		this.imageName = imageName;
	}

	public ImageIconWrapper(URL url) {
		if (url == null) {
			throw new NullPointerException("Cannot create an ImageIconWrapper from a null URL");
		}
		imageURL = url;
		imageName = imageURL.toExternalForm();
	}

	@Override
	public String getFilename() {
		return imageName;
	}

	public String getImageName() {
		return imageName;
	}

	@Override
	public Image getImage() {
		init();
		return image;
	}

	@Override
	public AccessibleContext getAccessibleContext() {
		init();
		return icon.getAccessibleContext();
	}

	@Override
	public String getDescription() {
		init();
		return icon.getDescription();
	}

	@Override
	public int getIconHeight() {
		init();
		return icon.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		init();
		return icon.getIconWidth();
	}

	@Override
	public int getImageLoadStatus() {
		init();
		return icon.getImageLoadStatus();
	}

	@Override
	public ImageObserver getImageObserver() {
		init();
		return icon.getImageObserver();
	}

	@Override
	public synchronized void paintIcon(Component c, Graphics g, int x, int y) {
		init();
		super.paintIcon(c, g, x, y);
	}

	@Override
	public void setDescription(String description) {
		init();
		icon.setDescription(description);
	}

	@Override
	public void setImage(Image image) {
		init();
		this.image = image;
		super.setImage(image);
	}

	@Override
	public String toString() {
		init();
		return icon.toString();
	}

	private synchronized void init() {
		if (!loaded) {
			loaded = true;
			icon = createImageIcon();
			image = icon.getImage();
			super.setImage(image);
		}
	}

	private void initializeImageBytes() {
		if (imageBytes != null) {
			return;
		}

		// must be from a URL
		imageBytes = loadBytesFromURL(imageURL);
	}

	private byte[] loadBytesFromURL(URL url) {
		InputStream is = null;
		ByteArrayOutputStream os = null;
		try {
			os = new ByteArrayOutputStream();
			is = url.openStream();
			int length = 0;
			byte[] buf = new byte[1024];
			while ((length = is.read(buf)) > 0) {
				os.write(buf, 0, length);
			}
			return os.toByteArray();

		}
		catch (IOException e) {
			Msg.error(this, "Exception loading image bytes: " + url.toExternalForm(), e);
		}
		finally {
			try {
				if (os != null) {
					os.close();
				}
			}
			catch (IOException e) {
				// we tried
			}

			try {
				if (is != null) {
					is.close();
				}
			}
			catch (IOException e) {
				// we tried
			}
		}
		return null;
	}

	private ImageIcon createImageIcon() {
		initializeImageBytes();

		if (imageBytes == null || imageBytes.length == 0) {
			ImageIcon defaultIcon = ResourceManager.getDefaultIcon();
			if (this == defaultIcon) {
				// this can happen under just the right conditions when loading the default 
				// icon's bytes fails (probably due to disk or network issues)
				throw new IllegalStateException("Unexpected failure loading the default icon!");
			}

			return defaultIcon; // some sort of initialization has failed
		}

		Image imageFromBytes = Toolkit.getDefaultToolkit().createImage(imageBytes);
		ImageIcon newImageIcon = ResourceManager.getImageIconFromImage(imageName, imageFromBytes);
		if (this == newImageIcon) {
			// just as above, this can happen under just the right conditions when loading 
			// the default icon's bytes fails (probably due to disk or network issues or
			// debugging in an IDE)
			throw new IllegalStateException("Unexpected failure loading icon: '" + imageName + "'");
		}
		return newImageIcon;
	}
}
