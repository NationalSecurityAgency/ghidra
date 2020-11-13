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
package generic.util.image;

import java.awt.*;
import java.awt.image.*;
import java.io.File;
import java.io.IOException;
import java.util.Objects;

import javax.imageio.ImageIO;
import javax.swing.*;

import ghidra.util.MathUtilities;
import ghidra.util.Msg;

public class ImageUtils {

	private static final float DEFAULT_TRANSPARENCY_ALPHA = 0.4f;

	/**
	 * A component to pass into the media tracker, as required by the constructor of the 
	 * MediaTracker.
	 */
	private static JComponent mediaTrackerComponent;

	private ImageUtils() {
		// no
	}

	/**
	 * Creates an image of the given component
	 * 
	 * @param c the component
	 * @return the image
	 */
	public static Image createImage(Component c) {

		// prevent this from being called when the user has made the window too small to work
		Rectangle bounds = c.getBounds();
		int w = Math.max(bounds.width, 1);
		int h = Math.max(bounds.height, 1);

		BufferedImage bufferedImage = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics g = bufferedImage.getGraphics();
		c.paint(g);
		g.dispose();
		return bufferedImage;
	}

	/**
	 * Pads the given image with space in the amount given.
	 * 
	 * @param i the image to pad
	 * @param c the color to use for the padding background
	 * @param top the top padding
	 * @param left the left padding
	 * @param right the right padding
	 * @param bottom the bottom padding
	 * @return a new image with the given image centered inside of padding
	 */
	public static Image padImage(Image i, Color c, int top, int left, int right, int bottom) {
		int width = i.getWidth(null) + left + right;
		int height = i.getHeight(null) + top + bottom;
		BufferedImage newImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics g = newImage.getGraphics();
		g.setColor(c);
		g.fillRect(0, 0, width, height);
		g.drawImage(i, left, top, null);
		g.dispose();

		waitForImage(null, newImage);
		return newImage;
	}

	/**
	 * Crops the given image, keeping the given bounds
	 * 
	 * @param i the image to crop
	 * @param bounds the new bounds
	 * @return a new image based on the given image, cropped to the given bounds.
	 */
	public static Image crop(Image i, Rectangle bounds) {
		BufferedImage newImage =
			new BufferedImage(bounds.width, bounds.height, BufferedImage.TYPE_INT_ARGB);
		Graphics g = newImage.getGraphics();
		g.drawImage(i, -bounds.x, -bounds.y, null);
		waitForImage(null, newImage);
		return newImage;
	}

	/**
	 * Creates a new image of the given size.  This image is suitable for drawing operations.
	 * 
	 * @param width the width of the new image
	 * @param height the height of the new image
	 * @return a new image of the given size.  This image is suitable for drawing operations.
	 */
	public static BufferedImage createEmptyImage(int width, int height) {
		BufferedImage newImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics g = newImage.getGraphics();
		g.setColor(Color.WHITE);
		g.fillRect(0, 0, width, height);
		return newImage;
	}

	/**
	 * Places the two given images side-by-side into a new image.
	 * 
	 * @param left the left image
	 * @param right the right image
	 * @return a new image with the two given images side-by-side into a new image.
	 */
	public static Image placeImagesSideBySide(Image left, Image right) {
		int leftHeight = left.getHeight(null);
		int leftWidth = left.getWidth(null);
		int rightHeight = right.getHeight(null);
		int rightWidth = right.getWidth(null);
		int width = leftWidth + rightWidth;
		int height = Math.max(leftHeight, rightHeight);

		BufferedImage newImage = createEmptyImage(width, height);
		Graphics g = newImage.getGraphics();
		int y = 0;
		if (leftHeight < rightHeight) {
			y = (rightHeight - leftHeight) / 2; // center smaller image
		}

		g.drawImage(left, 0, y, null);

		y = 0;
		if (leftHeight > rightHeight) {
			y = (leftHeight - rightHeight) / 2;
		}

		g.drawImage(right, leftWidth, y, null);
		g.dispose();

		waitForImage(null, newImage);
		return newImage;
	}

	/**
	 * Turns the given image into a {@link RenderedImage}
	 * 
	 * @param image the image
	 * @return the rendered image
	 */
	public static RenderedImage toRenderedImage(Image image) {
		if (image instanceof RenderedImage) {
			return (RenderedImage) image;
		}

		return getBufferedImage(image);
	}

	/**
	 * Copies this image into a buffered image.  If this image is already a buffered image, then
	 * it will be returned.
	 * 
	 * @param image the image
	 * @return the buffered image
	 */
	public static BufferedImage getBufferedImage(Image image) {
		if (image instanceof BufferedImage) {
			return (BufferedImage) image;
		}

		boolean success = waitForImage("<unknown name>", image);
		if (!success) {
			return null;
		}

		int width = image.getWidth(null);
		int height = image.getHeight(null);

		BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = bufferedImage.getGraphics();
		graphics.drawImage(image, 0, 0, null);
		graphics.dispose();
		return bufferedImage;
	}

	/**
	 * Waits a reasonable amount of time for the given image to load
	 *  
	 * @param imageName the name of the image
	 * @param image the image for which to wait
	 * @return true if the wait was successful
	 */
	public static boolean waitForImage(String imageName, Image image) {

		if (image instanceof BufferedImage) {
			return true;
		}

		if (image.getWidth(null) > 0 && image.getHeight(null) > 0) {
			return true;
		}

		MediaTracker tracker = new MediaTracker(getMediaTrackerComponent());
		int maxWaits = 20; // 2 seconds...not sure if we can ever hit this limit
		int waitTime = 100;
		tracker.addImage(image, 0);
		for (int i = 0; i < maxWaits; i++) {
			try {
				tracker.waitForID(0, waitTime);
				int width = image.getWidth(null);
				int height = image.getHeight(null);
				if (width < 0 || height < 0) {
					continue; // try again
				}
				tracker.removeImage(image, 0);
				return true;
			}
			catch (InterruptedException e) {
				// don't care; try again
			}

		}

		Msg.debug(ImageUtils.class, "Timed-out waiting for image to load after " +
			((maxWaits * waitTime) / 1000) + " seconds; " + imageName);
		tracker.removeImage(image, 0);
		return false;
	}

	/**
	 * Write the specified image to file in PNG format
	 * @param i the image to save
	 * @param imageFile the file to save the image to
	 * @throws IOException
	 */
	public static void writeFile(Image i, File imageFile) throws IOException {
		ImageIO.write(toRenderedImage(i), "png", imageFile);
	}

	/**
	 * Write the specified image to file in PNG format
	 * @param i the image to save
	 * @param imageFile the file to save the image to
	 * @throws IOException
	 */
	public static void writeFile(RenderedImage i, File imageFile) throws IOException {
		ImageIO.write(i, "png", imageFile);
	}

	/**
	 * Load an image from a file
	 * @param imageFile image source-data file
	 * @return the image, decoded from bytes in specified file
	 * @throws IOException
	 */
	public static BufferedImage readFile(File imageFile) throws IOException {
		return ImageIO.read(imageFile);
	}

	/**
	 * Writes the given icon out to the file denoted by <code>filename</code> <b> in the PNG format</b>.
	 * 
	 * @param icon the icon to write
	 * @param filename the filename denoting the write destination
	 * @throws IOException see {@link ImageIO#write(RenderedImage, String, File)}
	 */
	public static void writeIconToPNG(Icon icon, String filename) throws IOException {
		BufferedImage buffi = new BufferedImage(icon.getIconWidth(), icon.getIconHeight(),
			BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = buffi.getGraphics();
		icon.paintIcon(null, graphics, 0, 0);
		ImageIO.write(buffi, "png", new File(filename)); // throws exception
		graphics.dispose();
	}

	/**
	 * Make the specified icon semi-transparent using the default transparency alpha
	 * @param icon The icon to make semi-transparent
	 * @return a new icon, based on the original, made semi-transparent
	 * @see ImageUtils#DEFAULT_TRANSPARENCY_ALPHA 
	 */
	public static Icon makeTransparent(Icon icon) {
		return makeTransparent(icon, DEFAULT_TRANSPARENCY_ALPHA);
	}

	/**
	 * Make the specified icon semi-transparent using the specified transparency alpha
	 * 
	 * @param icon the icon to make semi-transparent
	 * @param alpha the alpha value to use in making the icon transparent 
	 * @return a new icon, based on the original, made semi-transparent
	 */
	public static Icon makeTransparent(Icon icon, float alpha) {
		BufferedImage newImage = new BufferedImage(icon.getIconWidth(), icon.getIconHeight(),
			BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = newImage.createGraphics();
		g.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, alpha));
		icon.paintIcon(null, g, 0, 0);
		g.dispose();

		return new ImageIcon(newImage);
	}

	/**
	 * Creates a scaled image based upon the given image.
	 * NOTE: Avoid invocation by a static initializer.
	 * @param image the image to scale
	 * @param width the new width
	 * @param height the new height
	 * @param hints {@link RenderingHints} used by {@link Graphics2D}
	 * @return a scaled version of the given image
	 */
	public static Image createScaledImage(Image image, int width, int height, int hints) {
		BufferedImage scaledImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = scaledImage.getGraphics();
		Graphics2D g2 = (Graphics2D) graphics;
		g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
			RenderingHints.VALUE_INTERPOLATION_BILINEAR);
		graphics.drawImage(image, 0, 0, width, height, null);
		graphics.dispose();
		return scaledImage;
	}

	/**
	 * Creates a disabled version of the given image.  The disabled version will be grayed
	 * and have the varying gray levels blended together.
	 * 
	 * @param image the image to disable
	 * @param brightnessPercent the amount of brightness to apply; 0-100
	 * @return the new image
	 */
	public static Image createDisabledImage(Image image, final int brightnessPercent) {

		Objects.requireNonNull(image);

		BufferedImage srcImage = new BufferedImage(image.getWidth(null), image.getHeight(null),
			BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = srcImage.getGraphics();
		graphics.drawImage(image, 0, 0, null);
		graphics.dispose();

		BufferedImage destImage = new BufferedImage(image.getWidth(null), image.getHeight(null),
			BufferedImage.TYPE_INT_ARGB);
		LookupTable table = new LookupTable(0, 4) {
			@Override
			// overridden to pass in the complete pixel data
			public int[] lookupPixel(int[] src, int[] dest) {
				return filterRgbDisabledImage(src, dest, brightnessPercent);
			}
		};

		LookupOp lookupOp = new LookupOp(table, null);
		lookupOp.filter(srcImage, destImage);
		return destImage;
	}

	/**
	 * Creates a new image that is the same as the given image but has the given colored 
	 * pixels replaced with the given new color
	 * 
	 * @param image the image to change
	 * @param oldColor the color to replace
	 * @param newColor the color to use
	 * @return the new image
	 */
	public static Image changeColor(Image image, Color oldColor, Color newColor) {
		Objects.requireNonNull(image);

		BufferedImage srcImage = new BufferedImage(image.getWidth(null), image.getHeight(null),
			BufferedImage.TYPE_INT_ARGB);
		Graphics graphics = srcImage.getGraphics();
		graphics.drawImage(image, 0, 0, null);
		graphics.dispose();

		int[] oldRgb = new int[] { oldColor.getRed(), oldColor.getGreen(), oldColor.getBlue() };
		int[] newRgb = new int[] { newColor.getRed(), newColor.getGreen(), newColor.getBlue() };

		BufferedImage destImage = new BufferedImage(image.getWidth(null), image.getHeight(null),
			BufferedImage.TYPE_INT_ARGB);
		LookupTable table = new LookupTable(0, 4) {
			@Override
			// overridden to pass in the complete pixel data
			public int[] lookupPixel(int[] src, int[] dest) {
				return filterRgbChangeColor(src, dest, oldRgb, newRgb);
			}
		};

		LookupOp lookupOp = new LookupOp(table, null);
		lookupOp.filter(srcImage, destImage);
		return destImage;
	}

	private static synchronized JComponent getMediaTrackerComponent() {
		if (mediaTrackerComponent == null) {
			mediaTrackerComponent = new JComponent() {
				// dummy component
			};
		}
		return mediaTrackerComponent;
	}

	/**
	 * Takes in RGB pixel data and then converts the pixel into a gray color with a brightness
	 * based upon <code>brightnessPercent</code>.
	 *  
	 * @param rgbPixels The RGB pixel data for a given pixel.
	 * @param destination The converted pixel data.
	 * @param brightnessPercent The amount of brightness to include in the gray value, where 100
	 *        percent is the brightest possible value.
	 * @return The <code>destination</code> array filled with the new pixel data.
	 */
	private static int[] filterRgbDisabledImage(int[] rgbPixels, int[] destination,
			int brightnessPercent) {

		// preserve the luminance
		// Humans have the most sensitivity to green, least sensitivity to blue
		int r = (int) (0.30 * (rgbPixels[0] & 0xff));
		int g = (int) (0.59 * (rgbPixels[1] & 0xff));
		int b = (int) (0.11 * (rgbPixels[2] & 0xff));

		// average the values together to blend the pixels so that the image is not as crisp
		int gray = (r + g + b) / 3;

		gray = (255 - ((255 - gray) * (100 - brightnessPercent) / 100));
		gray = MathUtilities.clamp(gray, 0, 255);

		destination[0] = gray;
		destination[1] = gray;
		destination[2] = gray;
		destination[3] = rgbPixels[3];
		return destination;
	}

	private static int[] filterRgbChangeColor(int[] rgbPixels, int[] destination, int[] oldRgb,
			int[] newRgb) {

		int r = rgbPixels[0] & 0xff;
		int g = rgbPixels[1] & 0xff;
		int b = rgbPixels[2] & 0xff;

		int oldR = oldRgb[0];
		int oldG = oldRgb[1];
		int oldB = oldRgb[2];

		if (r == oldR && g == oldG && b == oldB) {
			destination[0] = newRgb[0];
			destination[1] = newRgb[1];
			destination[2] = newRgb[2];
		}
		else {
			destination[0] = r;
			destination[1] = g;
			destination[2] = b;
		}

		destination[3] = rgbPixels[3];
		return destination;
	}
}
