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

import java.net.URL;

import javax.swing.ImageIcon;

/**
 * A class that knows how to provide an icon and the URL for that icon
 */
public class IconProvider {

	private ImageIcon icon;
	private URL url;

	public IconProvider(ImageIcon icon, URL url) {
		this.icon = icon;
		this.url = url;
	}

	public ImageIcon getIcon() {
		return icon;
	}

	public URL getUrl() {
		return url;
	}

	public boolean isInvalid() {
		return icon == null || url == null;
	}
}
