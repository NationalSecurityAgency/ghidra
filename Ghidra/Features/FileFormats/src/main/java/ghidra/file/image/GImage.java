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
package ghidra.file.image;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageOutputStream;
import javax.imageio.stream.MemoryCacheImageOutputStream;
import javax.swing.Icon;
import javax.swing.ImageIcon;

public class GImage {
	private int width;
	private int height;
	private int [] array;

	public GImage(int width, int height, GImageFormat format, InputStream data, long dataLength) throws IOException {
		this.width = width;
		this.height = height;
		this.array = packDataIntoArray(format, data, dataLength);
	}

	public Icon toPNG() throws IOException {
		ImageWriter imageWriter = getImageWriter("png");
		return getIcon(imageWriter);
	}

	public Icon toGIF() throws IOException {
		ImageWriter imageWriter = getImageWriter("gif");
		return getIcon(imageWriter);
	}

	public Icon toJPEG() throws IOException {
		ImageWriter imageWriter = getImageWriter("jpeg");
		return getIcon(imageWriter);
	}

	private Icon getIcon(ImageWriter imageWriter) throws IOException {
		GraphicsEnvironment gEnv = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice gDev = gEnv.getDefaultScreenDevice();
		GraphicsConfiguration gConfig = gDev.getDefaultConfiguration();

		BufferedImage bufferedImage = gConfig.createCompatibleImage(width, height, Transparency.TRANSLUCENT);
		bufferedImage.setRGB(0, 0, width, height, array, 0, width);

		OutputStream out = new ByteArrayOutputStream();
		ImageOutputStream imageOut = new MemoryCacheImageOutputStream(out);

		imageWriter.setOutput(imageOut);

		try {
			imageWriter.write(bufferedImage);
		}
		finally {
			imageOut.close();
		}

		Icon icon = new ImageIcon(bufferedImage);
		return icon;
	}

	private ImageWriter getImageWriter(String format) throws IOException {
		Iterator<ImageWriter> imageWriters = ImageIO.getImageWritersByFormatName(format);
		if (!imageWriters.hasNext()) {
			throw new IOException("No image writer found for PNG.");
		}
		ImageWriter imageWriter = imageWriters.next();
		return imageWriter;
	}

	private int [] packDataIntoArray(GImageFormat format, InputStream data, long dataLength) throws IOException {
		int offset = 0;
		int [] arr = new int[width * height];
		for (int i = 0 ; i < arr.length ; ++i) {

			if (format == GImageFormat.RGB_ALPHA_4BYTE) {
				int blue  = 0;
				int green = 0;
				int red   = 0;
				int alpha = 0;

				if (offset < dataLength) {
					blue  = data.read() & 0xff;
					green = data.read() & 0xff;
					red   = data.read() & 0xff;
					alpha = data.read() & 0xff;
				}

				alpha = ~alpha;//bit invert the alpha byte...

				int alpha_shifted = (alpha << 24) & 0xff000000;
				int   red_shifted = (red   << 16) & 0x00ff0000;
				int green_shifted = (green <<  8) & 0x0000ff00;
				int  blue_shifted = (blue  <<  0) & 0x000000ff;

				int argbValue = alpha_shifted | red_shifted | green_shifted | blue_shifted;

				arr[i] = argbValue;

				offset += 4;
			}
			else if (format == GImageFormat.GRAY_ALPHA_2BYTE) {
				int alpha = 0;
				int gray  = 0;

				if (offset < dataLength) {
					alpha = data.read() & 0xff;
					gray  = data.read() & 0xff;
				}

				alpha = ~alpha;//bit invert the alpha byte...

				int alpha_shifted = (alpha << 24) & 0xff000000;
				int   red_shifted = (gray  << 16) & 0x00ff0000;
				int green_shifted = (gray  <<  8) & 0x0000ff00;
				int  blue_shifted = (gray  <<  0) & 0x000000ff;

				int argbValue = alpha_shifted | red_shifted | green_shifted | blue_shifted;

				arr[i] = argbValue;

				offset += 2;
			}
		}
		return arr;
	}
}
