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

import java.awt.image.BufferedImage;
import java.awt.image.Raster;
import java.io.*;

import javax.imageio.ImageIO;
import javax.swing.*;

public class GImageConverter {
	private File imageFile;

	public GImageConverter(File imageFile) {
		this.imageFile = imageFile;
	}

	public byte [] toBufferedImage() throws IOException {
		BufferedImage bufferedImage = ImageIO.read(imageFile);

		if (bufferedImage == null) {
			throw new IOException("No image provider for "+imageFile.getName());
		}

		/*TODO
		int type = bufferedImage.getType();

		if (type != BufferedImage.TYPE_4BYTE_ABGR &&
			type != BufferedImage.TYPE_USHORT_GRAY) {
			String message = ClassFieldInspector.toString(BufferedImage.class, "TYPE_", type);
			throw new IOException("Invalid type detected: "+message);
		}
		*/

		int width  = bufferedImage.getWidth();
		int height = bufferedImage.getHeight();

		Raster raster = bufferedImage.getData();
		int [] pixels = raster.getPixels(0, 0, width, height, (int [])null);

		ByteArrayOutputStream out = new ByteArrayOutputStream();

		for (int p = 0 ; p < pixels.length ; ) {

			int blue  = pixels[p + 0] & 0xff;
			int green = pixels[p + 1] & 0xff;
			int red   = pixels[p + 2] & 0xff;
			int alpha = pixels[p + 3] & 0xff;

			alpha = ~alpha;//bit invert the alpha byte...

			out.write(red);
			out.write(green);
			out.write(blue);
			out.write(alpha);

			p += 4;
		}

		out.close();

		return out.toByteArray();
	}

	private int getWidth() throws IOException {
		BufferedImage bufferedImage = ImageIO.read(imageFile);
		return bufferedImage.getWidth();
	}

	private int getHeight() throws IOException {
		BufferedImage bufferedImage = ImageIO.read(imageFile);
		return bufferedImage.getHeight();		
	}

	public static void main(String [] args) throws Exception {
		GImageFormat format = GImageFormat.GRAY_ALPHA_2BYTE;

		String img = "~/Mobile_Devices/images/apple_logo_line_1.PNG";
		String raw = "~/Mobile_Devices/images/apple_logo_line_1.RAW";

		File imageFile = new File(img);

		GImageConverter converter = new GImageConverter(imageFile);
		byte [] imageBytes = converter.toBufferedImage();

		OutputStream rawOUT = new FileOutputStream(raw);
		rawOUT.write(imageBytes);
		rawOUT.close();

		File rawFile = new File(raw);
		InputStream rawIN = new FileInputStream(raw);

		GImage image = new GImage(converter.getWidth(), converter.getHeight(), format, rawIN, rawFile.length());

		rawIN.close();

		final Icon icon = image.toPNG();

		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				JOptionPane.showMessageDialog(null, icon, "icon", JOptionPane.INFORMATION_MESSAGE);
			}
		});
	}
}
