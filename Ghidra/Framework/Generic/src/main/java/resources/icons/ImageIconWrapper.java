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
import java.awt.image.BufferedImage;
import java.awt.image.ImageObserver;
import java.io.*;
import java.net.URL;
import java.util.Objects;

import javax.accessibility.AccessibleContext;
import javax.swing.Icon;
import javax.swing.ImageIcon;

import generic.util.image.ImageUtils;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * <code>ImageIconWrapper</code> provides the ability to instantiate 
 * an ImageIcon with delayed loading.  In addition to delayed loading
 * it has the added benefit of allowing the use of static initialization
 * of ImageIcons without starting the Swing thread which can cause
 * problems when running headless.
 */
public class ImageIconWrapper extends ImageIcon implements FileBasedIcon {

	private boolean loaded;
	private ImageIcon imageIcon;

	private Image image;

	private Image baseImage;
	private Icon baseIcon;
	private byte[] imageBytes;
	private URL imageURL;
	private String imageName; // lazy load

	/**
	 * Construct wrapped ImageIcon based upon specified image byte array
	 * (see {@link Toolkit#createImage(byte[])})
	 * @param imageBytes image bytes
	 * @param imageName image reference name
	 */
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

	/**
	 * Construct wrapped ImageIcon based upon specified image
	 * @param image icon image
	 * @param imageName image reference name
	 */
	public ImageIconWrapper(Image image, String imageName) {
		Objects.requireNonNull(image, "Cannot create an ImageIconWrapper from a null image");
		this.baseImage = image;
		this.imageName = imageName;
	}

	/**
	 * Construct wrapped ImageIcon based upon specified icon
	 * which may require transformation into ImageIcon
	 * @param icon the icon
	 */
	public ImageIconWrapper(Icon icon) {
		this.baseIcon = icon;
	}

	/**
	 * Construct wrapped ImageIcon based upon specified resource URL
	 * @param url icon image resource URL
	 */
	public ImageIconWrapper(URL url) {
		Objects.requireNonNull(url, "Cannot create an ImageIconWrapper from a null URL");
		imageURL = url;
		imageName = imageURL.toExternalForm();
	}

	private synchronized void init() {
		if (!loaded) {
			loaded = true;
			imageIcon = createImageIcon();
			image = imageIcon.getImage();
			super.setImage(image);
		}
	}

	@Override
	public String getFilename() {
		return getImageName();
	}

	/**
	 * Get icon reference name
	 * @return icon name
	 */
	public String getImageName() {
		if (imageName == null && baseIcon != null) {
			imageName = ResourceManager.getIconName(baseIcon);
		}
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
		return imageIcon.getAccessibleContext();
	}

	@Override
	public String getDescription() {
		init();
		return imageIcon.getDescription();
	}

	@Override
	public int getIconHeight() {
		init();
		return imageIcon.getIconHeight();
	}

	@Override
	public int getIconWidth() {
		init();
		return imageIcon.getIconWidth();
	}

	@Override
	public int getImageLoadStatus() {
		init();
		return imageIcon.getImageLoadStatus();
	}

	@Override
	public ImageObserver getImageObserver() {
		init();
		return imageIcon.getImageObserver();
	}

	@Override
	public synchronized void paintIcon(Component c, Graphics g, int x, int y) {
		init();
		super.paintIcon(c, g, x, y);
	}

	@Override
	public void setDescription(String description) {
		init();
		imageIcon.setDescription(description);
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
		return imageIcon.toString();
	}

	private byte[] loadBytesFromURL(URL url) {
		try (InputStream is = url.openStream()) {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
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
		return null;
	}

	/**
	 * Get the base icon image to be transformed in ImageIcon
	 * @return the base icon image to be transformed in ImageIcon
	 */
	protected final Image createIconBaseImage() {

		if (baseImage != null) {
			return baseImage;
		}
		if (baseIcon != null) {
			BufferedImage bufferedImage = new BufferedImage(baseIcon.getIconWidth(),
				baseIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
			Graphics graphics = bufferedImage.getGraphics();
			baseIcon.paintIcon(null, graphics, 0, 0);
			graphics.dispose();
			return bufferedImage;
		}
		if (imageBytes == null || imageBytes.length == 0) {
			imageBytes = loadBytesFromURL(imageURL);
			if (imageBytes == null) {
				return null;
			}
		}
		return Toolkit.getDefaultToolkit().createImage(imageBytes);
	}

	protected ImageIcon createImageIcon() {

		if (baseIcon instanceof ImageIcon) {
			return (ImageIcon) baseIcon;
		}

		Image iconImage = createIconBaseImage();
		if (iconImage == null) {
			return getDefaultIcon();
		}

		String name = getImageName();
		if (!ImageUtils.waitForImage(name, iconImage)) {
			return getDefaultIcon(); // rather than returning null we will give a reasonable default
		}
		return new ImageIcon(iconImage, name);
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
