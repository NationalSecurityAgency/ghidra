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
import java.awt.Toolkit;
import java.io.*;
import java.net.URL;
import java.util.Objects;

import javax.swing.ImageIcon;

import generic.util.image.ImageUtils;
import ghidra.util.Msg;

/**
 * {@link LazyImageIcon} that is created from a URL to an icon file.
 */
public class UrlImageIcon extends LazyImageIcon {
	private URL imageUrl;

	/**
	 * Constructor
	 * @param path the path String used to create the URL
	 * @param url the {@link URL} to an icon resource file
	 */
	public UrlImageIcon(String path, URL url) {
		super(path);
		this.imageUrl = Objects.requireNonNull(url);
	}

	public URL getUrl() {
		return imageUrl;
	}

	@Override
	protected ImageIcon createImageIcon() {
		String name = getFilename();
		Image image = createImage();
		if (image == null) {
			return null;
		}
		if (!ImageUtils.waitForImage(name, image)) {
			return null;
		}
		return new ImageIcon(image, name);
	}

	protected Image createImage() {
		byte[] imageBytes = loadBytesFromURL(imageUrl);
		if (imageBytes == null) {
			return null;
		}
		return Toolkit.getDefaultToolkit().createImage(imageBytes);
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
}
