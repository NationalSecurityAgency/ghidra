/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.io;

import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.*;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

/**
 * JarWriter is a class for writing to a jar output stream.
 */
public class JarWriter {

	protected JarOutputStream jarOut;
	private String[] excludedExtensions;

	/**
	 * @param jarOut the the jar file output stream the zip entries are
	 * to be written to.
	 */
	public JarWriter(JarOutputStream jarOut) {
		this(jarOut, new String[0]);
	}

	public JarWriter(JarOutputStream jarOut, String[] excludedExtensions) {
		this.jarOut = jarOut;
		this.excludedExtensions = excludedExtensions;
	}

	/**
	 * Outputs an individual file to the jar.
	 * 
	 * @param baseFile the file to be output
	 * @param jarPath the base path to prepend to the file as it is written
	 * to the jar output stream.
	 * @param monitor cancellable task monitor
	 * @return true if file is output to the jar file successfully.
	 */
	public boolean outputFile(File baseFile, String jarPath, TaskMonitor monitor) {
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

		try {
			return outputEntry(jarPath + baseFile.getName(), baseFile.lastModified(), in, monitor);
		}
		finally {
			try {
				in.close();
			}
			catch (IOException ioe) {
				Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
			}
		}
	}

	/**
	 * Outputs an individual entry to the jar.  The data input stream will be read until and EOF is read.
	 * @param path entry path within the jar file
	 * @param time entry time
	 * @param in data input stream
	 * @param monitor cancellable task monitor
	 * @return true if entry is output to the jar file successfully.
	 */
	public boolean outputEntry(String path, long time, InputStream in, TaskMonitor monitor) {

		byte[] bytes = new byte[4096];
		int numRead = 0;

		//Create a zip entry and write it out along with its data.
		ZipEntry entry = new ZipEntry(path);
		entry.setTime(time);
		try {
			monitor.setMessage("Writing " + path);
			jarOut.putNextEntry(entry);
			try {
				while ((numRead = in.read(bytes)) != -1) {
					if (monitor.isCancelled()) {
						return false;
					}
					jarOut.write(bytes, 0, numRead);
				}
				return true;
			}
			catch (IOException ioe) {
				Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
			}
			finally {
				jarOut.closeEntry();
			}
		}
		catch (IOException ioe) {
			Msg.error(this, "Unexpected Exception: " + ioe.getMessage(), ioe);
		}
		return false;
	}

	/**
	 * Recursively outputs a directory to the jar output stream
	 * If baseFile is a file then it is simply output to the jar.
	 * 
	 * @param baseFile the file or directory to be output
	 * @param jarPath the base path to prepend to the files as they are written
	 * to the jar output stream.
	 * 
	 * @return true if all files are recursively output to the jar file.
	 */
	public boolean outputRecursively(File baseFile, String jarPath, TaskMonitor monitor) {

		boolean succeeded = true;
		File[] subFiles = new File[0];

		if (baseFile.isDirectory()) {
			subFiles = baseFile.listFiles();
			for (int i = 0; i < subFiles.length; i++) {
				if (monitor.isCancelled()) {
					break;
				}
				String newPath = jarPath + baseFile.getName() + File.separator;
				succeeded = outputRecursively(subFiles[i], newPath, monitor) && succeeded;
			}
		}
		else {
			String name = baseFile.getName();
			for (int i = 0; i < excludedExtensions.length; i++) {
				if (name.endsWith(excludedExtensions[i])) {
					return true;
				}
			}
			succeeded = outputFile(baseFile, jarPath, monitor);
		}
		return succeeded;
	}

	/**
	 * Return the jar output stream being used by this JarWriter.
	 */
	public JarOutputStream getJarOutputStream() {
		return jarOut;
	}

	/**
	 * Simple test for the JarWriter
	 * @param args args[0] is the source directory, args[1] is the output filename
	 */
	public static void main(String[] args) {

		if (args.length != 2) {
			System.out.println("Usage: java JarWriter [sourceDir] [outputFilename]");
			System.exit(0);
		}
		try {
			JarOutputStream jarOut = new JarOutputStream(new FileOutputStream(args[1]));
			JarWriter writer = new JarWriter(jarOut);
			writer.outputRecursively(new File(args[0]), "", TaskMonitorAdapter.DUMMY_MONITOR);
			jarOut.close();
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}

	}
}
