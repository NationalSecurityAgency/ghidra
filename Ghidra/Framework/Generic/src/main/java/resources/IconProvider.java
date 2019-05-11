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
package resources;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import javax.swing.ImageIcon;

import generic.Images;
import generic.util.image.ImageUtils;
import ghidra.util.Msg;

/**
 * A class that knows how to provide an icon and the URL for that icon.  If {@link #getUrl()}
 * returns a non-null value, then that is the URL used to originally load the icon in this class.
 * 
 * <p>If {@link #getUrl()} returns null, then {@link #getOrCreateUrl()} can be used to create a
 * value URL by writing out the image for this class's icon.
 */
public class IconProvider {

	private ImageIcon icon;
	private URL url;
	private URL tempUrl;
	private boolean tempFileFailed;

	public IconProvider(ImageIcon icon, URL url) {
		this.icon = icon;
		this.url = url;
	}

	public ImageIcon getIcon() {
		return icon;
	}

	public boolean isInvalid() {
		return icon == null; // as long as we have an icon, we are valid, url or not
	}

	public URL getUrl() {
		return url;
	}

	/**
	 * Returns the value of {@link #getUrl()} if it is non-null.  Otherwise, this class will
	 * attempt to create a temporary file containing the image of this class in order to return
	 * a URL for that temp file.  If a temporary file could not be created, then the URL 
	 * returned from this class will point to the 
	 * {@link ResourceManager#getDefaultIcon() default icon}.
	 * 
	 * @return the URL
	 */
	public URL getOrCreateUrl() {
		if (url != null) {
			return url;
		}

		createTempUrlAsNeeded();
		return tempUrl;
	}

	private void createTempUrlAsNeeded() {
		if (testUrl(tempUrl)) {
			return;
		}

		tempUrl = createTempUrl();
		if (tempUrl == null) {
			tempUrl = getDefaultUrl();
		}
	}

	private URL createTempUrl() {
		if (tempFileFailed) {
			return null; // don't repeatedly attempt to create a temp file
		}

		try {
			File imageFile = File.createTempFile("temp.help.icon", null);
			imageFile.deleteOnExit(); // don't let this linger
			ImageUtils.writeFile(icon.getImage(), imageFile);
			return imageFile.toURI().toURL();
		}
		catch (IOException e) {
			tempFileFailed = true;
			Msg.error(this, "Unable to write temp image to display in help for " +
				ResourceManager.getIconName(icon));
		}
		return null;
	}

	private boolean testUrl(URL testUrl) {
		if (testUrl == null) {
			return false;
		}

		try {
			return new File(testUrl.toURI()).exists();
		}
		catch (URISyntaxException e) {
			return false;
		}
	}

	private URL getDefaultUrl() {
		return ResourceManager.getResource(Images.BOMB);
	}
}
