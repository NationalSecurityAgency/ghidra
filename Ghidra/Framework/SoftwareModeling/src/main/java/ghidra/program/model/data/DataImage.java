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
package ghidra.program.model.data;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;

public abstract class DataImage {

	private String description;

	/**
	 * Return image icon
	 * @return image object
	 */
	public abstract ImageIcon getImageIcon();

	/**
	 * Returns the type of the underlying image data, suitable for
	 * {@link ImageIO#write(java.awt.image.RenderedImage, String, java.io.File)}'s formatName
	 * parameter.
	 * 
	 * @return String image format type, ie. "png", "gif", "bmp"
	 */
	public abstract String getImageFileType();

	/**
	 * Set string description (returned by toString)
	 * @param description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	@Override
	public String toString() {
		if (description != null) {
			return description;
		}
		return new String("DataImage@" + Integer.toHexString(hashCode()));
	}

}
