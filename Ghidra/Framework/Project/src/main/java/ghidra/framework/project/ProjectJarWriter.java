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
package ghidra.framework.project;

import java.io.*;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

import generic.io.JarWriter;
import ghidra.util.Msg;

/**
 * Class to write files in a project to a jar output stream.
 */

class ProjectJarWriter extends JarWriter {

	private static final String PROPERTIES_FILE_NAME = ".properties";
	private static final String ORIGINAL_PROPERTIES_FILE_NAME = "original"+PROPERTIES_FILE_NAME;

	/**
	 * @param jarOut the the jar file output stream the zip entries are
	 * to be written to.
	 */
	ProjectJarWriter(JarOutputStream jarOut) {
		super(jarOut);
	}

    /**
     * Outputs an individual file to the jar.
     * 
     * @param baseFile the file to be output
     * @param jarPath the base path to prepend to the file as it is written
     * to the jar output stream.
     * 
     * @return true if all files are recursively output to the jar file.
     */
	boolean outputFile(File baseFile, String jarPath) {
		boolean succeeded = true;
		if (baseFile.isDirectory()) {
			return false;
		}

		FileInputStream in = null;
		try {
			in = new FileInputStream(baseFile);
		}
		catch (FileNotFoundException fnfe) {
			Msg.error(this, "Unexpected Exception: " + fnfe.getMessage(), fnfe);
			return false;
		}
		byte[] bytes = new byte[4096];
		int numRead = 0;
		//Create a zip entry and write it out along with its data.
		String name = baseFile.getName();
		if (name.equals(PROPERTIES_FILE_NAME)) {
			name = ORIGINAL_PROPERTIES_FILE_NAME;
		}
		ZipEntry entry = new ZipEntry(jarPath + name);
		entry.setComment("project file");
		try {
			jarOut.putNextEntry(entry);
			try {
				while ((numRead = in.read(bytes)) != -1) {
					jarOut.write(bytes, 0, numRead);
				}
			}
			catch (IOException ioe) {
				succeeded = false;
			}
			finally {
				jarOut.closeEntry();
			}
		}
		catch (IOException ioe) {
			succeeded = false;
			Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
		}
		finally {
			try {
				in.close();
			}
			catch (IOException ioe) {
				Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
			}
		}

		return succeeded;
	}

}
