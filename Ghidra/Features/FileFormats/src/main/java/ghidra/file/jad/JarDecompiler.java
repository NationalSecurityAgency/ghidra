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
package ghidra.file.jad;

import java.io.*;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.zip.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FalseFileFilter;
import org.apache.commons.io.filefilter.TrueFileFilter;

import ghidra.app.util.importer.MessageLog;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import utilities.util.FileUtilities;

/**
 * Given a JAR file, this class will recursively decompile it.
 */
public class JarDecompiler {

	/**
	 * Returns true if the filename appears to be a jar file
	 * @param filename string filename
	 * @return boolean true if it is probably a jar file
	 */
	public static boolean isJarFilename(String filename) {
		return "jar".equalsIgnoreCase(FilenameUtils.getExtension(filename));
	}

	private FSRL jarFile;
	private File outputDirectory;
	private MessageLog log = new MessageLog();

	public JarDecompiler(FSRL jarFile, File outputDirectory) {
		this.jarFile = jarFile;
		this.outputDirectory = outputDirectory;
	}

	public void decompile(TaskMonitor monitor) throws IOException, CancelledException {
		FileUtilities.checkedMkdirs(outputDirectory);
		monitor.setMessage("");
		unzip(monitor);
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage("");
		processListing(outputDirectory, monitor);
		monitor.setMessage("");
	}

	public MessageLog getLog() {
		return log;
	}

	private String getRelPath(File directory) {
		return directory.getPath().substring(outputDirectory.getPath().length());
	}

	private void processListing(File directory, TaskMonitor monitor) {

		// WARNING: this method starts a new thread for every directory found
		// in the extracted jar
		Iterator<File> iterator = FileUtils.iterateFilesAndDirs(directory, FalseFileFilter.INSTANCE,
			TrueFileFilter.INSTANCE);

		while (iterator.hasNext()) {
			File dir = iterator.next();
			Task task = new JarDecompilerTask(dir, jarFile.getName() + ":" + getRelPath(dir));
			TaskLauncher.launch(task);
		}
	}

	private void unzip(TaskMonitor monitor)
			throws ZipException, IOException, FileNotFoundException, CancelledException {

		File file = FileSystemService.getInstance().getFile(jarFile, monitor);
		ZipFile zipFile = new ZipFile(file);

		monitor.initialize(countZipEntries(zipFile, monitor));

		try {
			Enumeration<? extends ZipEntry> entries = zipFile.entries();
			while (entries.hasMoreElements()) {
				if (monitor.isCancelled()) {
					break;
				}
				ZipEntry zipEntry = entries.nextElement();
				File absoluteFile = new File(outputDirectory.getAbsolutePath(), zipEntry.getName());
				if (!FileUtilities.isPathContainedWithin(outputDirectory, absoluteFile)) {
					throw new IOException("Extracted file " + absoluteFile.getPath() +
						" would be outside of root destination directory: " + outputDirectory);
				}
				FileUtilities.checkedMkdirs(absoluteFile.getParentFile());
				if (!zipEntry.isDirectory()) {
					monitor.setMessage("Unzipping jar file... ");
					monitor.incrementProgress(1);
					writeFile(zipFile, zipEntry, absoluteFile, monitor);
				}
			}
		}
		finally {
			zipFile.close();
		}
	}

	private void writeFile(ZipFile zipFile, ZipEntry zipEntry, File absoluteFile,
			TaskMonitor monitor) throws IOException {
		byte[] bytes = new byte[0x100000];
		InputStream inputStream = zipFile.getInputStream(zipEntry);
		try {
			OutputStream outputStream = new FileOutputStream(absoluteFile);
			try {
				while (true) {
					if (monitor.isCancelled()) {
						break;
					}
					int nRead = inputStream.read(bytes);
					if (nRead == -1) {
						break;
					}
					outputStream.write(bytes, 0, nRead);
				}
			}
			finally {
				outputStream.close();
			}
		}
		finally {
			inputStream.close();
		}
	}

	private int countZipEntries(ZipFile zipFile, TaskMonitor monitor) {
		int count = 0;
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			if (monitor.isCancelled()) {
				break;
			}
			entries.nextElement();
			++count;
		}
		return count;
	}
}
