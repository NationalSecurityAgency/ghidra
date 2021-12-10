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
package ghidra.formats.gfilesystem;

import java.awt.Image;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.ImageIcon;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GFileSystem} add-on interface to allow filesystems to override how image files
 * are converted into viewable {@link Icon} instances.
 */
public interface GIconProvider {

	/**
	 * A method that {@link GFileSystem file systems} can implement if they need to preprocess
	 * image files so that Ghidra can display them.
	 *
	 * @param file {@link GFile} to read and convert into an Icon.
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @return new {@link Icon} instance with contents of the GFile.
	 * @throws IOException if problem reading or converting image.
	 * @throws CancelledException if user cancels.
	 */
	public Icon getIcon(GFile file, TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Helper static method that will get an Icon from a data file.
	 *
	 * @param file {@link GFile} to read and convert into an Icon.
	 * @param monitor {@link TaskMonitor} to watch and update with progress.
	 * @return new {@link Icon} instance with contents of the GFile, or null if the
	 * file couldn't be converted into an image.
	 * @throws CancelledException if the user cancels.
	 */
	public static Icon getIconForFile(GFile file, TaskMonitor monitor) throws CancelledException {
		try {
			GFileSystem fs = file.getFilesystem();
			if (fs instanceof GIconProvider) {
				return ((GIconProvider) fs).getIcon(file, monitor);
			}

			try (InputStream is = file.getFilesystem().getInputStream(file, monitor)) {
				Image image = ImageIO.read(is);
				if (image == null) {
					return null;
				}
				return new ImageIcon(image);
			}
			catch (Exception e) {
				Msg.error(GIconProvider.class, "Exception while reading image " + file.getName(),
					e);
			}
		}
		catch (IOException ioe) {
			// ignore
		}
		return null;
	}

}
