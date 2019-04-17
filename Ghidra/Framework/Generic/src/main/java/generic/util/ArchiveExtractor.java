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
package generic.util;

import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.Enumeration;
import java.util.zip.*;

import utilities.util.FileUtilities;

public class ArchiveExtractor {
	public static void explode(File baseDir, File archiveFile, TaskMonitor monitor)
			throws ZipException, IOException {

		ZipFile zipFile = new ZipFile(archiveFile);
		monitor.setIndeterminate(true);
		int count = getEntryCount(zipFile);
		monitor.initialize(count);

		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			ZipEntry entry = entries.nextElement();
			String path = entry.getName();
			File outputFile = new File(baseDir, path);
			InputStream inputStream = zipFile.getInputStream(entry);
			FileUtilities.copyStreamToFile(inputStream, outputFile, false,
				new CancelOnlyWrappingTaskMonitor(monitor));
			monitor.incrementProgress(1);
			if (monitor.isCancelled()) {
				break;
			}
		}
		zipFile.close();
	}

	private static int getEntryCount(ZipFile zipFile) {
		int count = 0;
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			entries.nextElement();
			count++;
		}
		return count;
	}
}
