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
package pdb;

import java.util.List;

import java.io.*;

import org.apache.commons.io.FilenameUtils;
import org.xml.sax.SAXException;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.formats.gfilesystem.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.*;
import utilities.util.FileUtilities;

public class PdbUtils {

	/**
	 * Attempts to extract {@link PdbIdentifiers} from the specified file, which
	 * can be either a pdb or pdb.xml file.
	 * <p>
	 * 
	 * @param file File to examine
	 * @param monitor {@link TaskMonitor}to allow cancel and progress
	 * @return new {@link PdbIdentifiers} instance with GUID/ID and age info, or null if
	 * not a valid pdb or pdb.xml file
	 */
	public static PdbIdentifiers getPdbIdentifiers(File file, TaskMonitor monitor) {
		String extension = FilenameUtils.getExtension(file.getName()).toLowerCase();
		switch (extension) {
			case "pdb":
				try (AbstractPdb pdb =
					PdbParser.parse(file.getPath(), new PdbReaderOptions(), monitor)) {
					PdbIdentifiers identifiers = pdb.getIdentifiers();
					return identifiers;
				}
				catch (Exception e) {
					return null;
				}
			case "xml":
				XmlPullParser parser = null;
				try {
					parser = XmlPullParserFactory.create(file, null, false);

					XmlElement xmlelem = parser.peek();

					if (!"pdb".equals(xmlelem.getName())) {
						return null;
					}

					String guidStr = xmlelem.getAttribute("guid");
					GUID guid = new GUID(guidStr);
					int age = Integer.parseInt(xmlelem.getAttribute("age"));

					return new PdbIdentifiers(0, 0, age, guid, null);
				}
				catch (SAXException | IOException | RuntimeException e) {
					// don't care, return null
					return null;
				}
				finally {
					if (parser != null) {
						parser.dispose();
					}
				}
			default:
				return null;
		}
	}

	/**
	 * Extracts a singleton file from a cab file that only has 1 file
	 *  
	 * @param cabFile Compressed cab file that only has 1 file embedded in it
	 * @param destFile where to write the extracted file to 
	 * @param monitor {@link TaskMonitor} to allow canceling
	 * @return original name of the file
	 * @throws CancelledException if cancelled
	 * @throws IOException if error reading / writing file or cab file has more than 1 file in it
	 */
	public static String extractSingletonCabToFile(File cabFile, File destFile, TaskMonitor monitor)
			throws CancelledException, IOException {
		FileSystemService fsService = FileSystemService.getInstance();
		FSRL cabFSRL = fsService.getLocalFSRL(cabFile);
		try (GFileSystem fs = fsService.openFileSystemContainer(cabFSRL, monitor)) {
			if (fs != null) {
				List<GFile> rootListing = fs.getListing(null);
				if (rootListing.size() == 1) {
					GFile f = rootListing.get(0);
					try (InputStream is = fs.getInputStream(f, monitor)) {
						FileUtilities.copyStreamToFile(is, destFile, false, monitor);
						return f.getName();
					}
				}
			}
		}
		throw new IOException("Unable to find file to extract");
	}

}
