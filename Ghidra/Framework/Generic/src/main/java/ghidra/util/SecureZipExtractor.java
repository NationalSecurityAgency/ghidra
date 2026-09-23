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
package ghidra.util;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.InputStreamStatistics;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * A utility class to safely extract zip files.
 * <p>
 * Protects against:
 * <ul>
 * <li><a href="https://en.wikipedia.org/wiki/Directory_traversal_attack">Zip Slip</a></li>
 * <li><a href="https://en.wikipedia.org/wiki/Zip_bomb">Zip Bomb</a></li>
 * </ul>
 */
public class SecureZipExtractor {

	private static final double MAX_THRESHOLD_RATIO = 100.0; // 100:1 ratio
	private static final long MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
	private static final long MAX_TOTAL_SIZE = 1024 * 1024 * 1024; // 1 GB

	/**
	 * Securely extracts the given zip file to the given directory
	 * 
	 * @param zipFile The zip {@link File} to extract
	 * @param targetDir The directory to unzip to
	 * @param monitor A cancellable {@link TaskMonitor}
	 * @throws IOException if a zip slip, zip bomb, or other IO-related error occurred
	 * @throws CancelledException if the operation was cancelled
	 */
	public static void extractSecurely(File zipFile, File targetDir, TaskMonitor monitor)
			throws IOException, CancelledException {

		try (ZipFile archive = ZipFile.builder().setFile(zipFile).get()) {
			long total = 0;
			Enumeration<ZipArchiveEntry> entries = archive.getEntries();

			while (entries.hasMoreElements()) {
				monitor.checkCancelled();

				ZipArchiveEntry entry = entries.nextElement();
				File outputFile = FileUtilities.getSecureFile(targetDir, entry.getName());

				if (entry.isDirectory()) {
					outputFile.mkdirs();
				}
				else {
					total += extractSecurely(archive, entry, outputFile.toPath(), total);
				}
			}
		}
	}

	/**
	 * Securely writes the given zip entry to the given output file. Assumes that the output file's
	 * directory exists.
	 * 
	 * @param archive The original {@link ZipFile} to extract from
	 * @param entry The {@link ZipArchiveEntry entry} to extract
	 * @param outputFile The {@link File} to extract the entry to
	 * @throws IOException if a zip bomb or other IO-related error occurred
	 */
	public static void extractSecurely(ZipFile archive, ZipArchiveEntry entry, File outputFile)
			throws IOException {
		extractSecurely(archive, entry, outputFile.toPath(), 0);
	}

	/**
	 * Securely writes the given zip entry to the given output path
	 * 
	 * @param archive The original {@link ZipFile} to extract from
	 * @param entry The {@link ZipArchiveEntry entry} to extract
	 * @param outputPath The {@link Path} to extract the entry to
	 * @param totalBytesExtracted The total number of bytes that have been extracted so far
	 * @return The number of bytes extracted for this entry
	 * @throws IOException if a zip bomb or other IO-related error occurred
	 */
	private static long extractSecurely(ZipFile archive, ZipArchiveEntry entry, Path outputPath,
			long totalBytesExtracted) throws IOException {

		try (InputStream is = archive.getInputStream(entry)) {
			if (!(is instanceof InputStreamStatistics stats)) {
				throw new IOException(
					"Stream does not support InputStreamStatistics tracking.");
			}

			try (OutputStream os = Files.newOutputStream(outputPath, StandardOpenOption.CREATE,
				StandardOpenOption.TRUNCATE_EXISTING)) {

				byte[] buffer = new byte[4096];
				int bytesRead;

				while ((bytesRead = is.read(buffer)) != -1) {
					os.write(buffer, 0, bytesRead);

					long uncompressed = stats.getUncompressedCount();
					long compressed = stats.getCompressedCount();

					// Check single file threshold
					if (uncompressed > MAX_SINGLE_FILE_SIZE) {
						throw new IOException(
							"Zip bomb detected: Single entry exceeds maximum allowed size.");
					}

					// Check total extraction threshold
					if (totalBytesExtracted + uncompressed > MAX_TOTAL_SIZE) {
						throw new IOException(
							"Zip bomb detected: Total extraction size exceeds limit.");
					}

					// Check compression ratio (only after sufficient data is read to avoid false positives)
					if (compressed > 1024) {
						double ratio = (double) uncompressed / compressed;
						if (ratio > MAX_THRESHOLD_RATIO) {
							throw new IOException(
								"Zip bomb detected: Compression ratio limits exceeded (" +
									ratio + ")");
						}
					}
				}
			}

			// Update its permissions (supported only on UNIX platforms)
			if (entry.getPlatform() == ZipArchiveEntry.PLATFORM_UNIX) {
				int mode = entry.getUnixMode();
				if (mode != 0) { // 0 indicates non-unix platform
					Set<PosixFilePermission> perms = getPermissions(mode);
					try {
						Files.setPosixFilePermissions(outputPath, perms);
					}
					catch (UnsupportedOperationException e) {
						// ignore error...possibly on Windows
					}
				}
			}

			return stats.getUncompressedCount();
		}
	}

	/**
	 * Converts Unix permissions to a set of {@link PosixFilePermission}s.
	 *
	 * @param unixMode integer representation of file permissions
	 * @return set of POSIX file permissions
	 */
	private static Set<PosixFilePermission> getPermissions(int unixMode) {

		Set<PosixFilePermission> permissions = new HashSet<>();

		if ((unixMode & 0400) != 0) {
			permissions.add(PosixFilePermission.OWNER_READ);
		}
		if ((unixMode & 0200) != 0) {
			permissions.add(PosixFilePermission.OWNER_WRITE);
		}
		if ((unixMode & 0100) != 0) {
			permissions.add(PosixFilePermission.OWNER_EXECUTE);
		}
		if ((unixMode & 0040) != 0) {
			permissions.add(PosixFilePermission.GROUP_READ);
		}
		if ((unixMode & 0020) != 0) {
			permissions.add(PosixFilePermission.GROUP_WRITE);
		}
		if ((unixMode & 0010) != 0) {
			permissions.add(PosixFilePermission.GROUP_EXECUTE);
		}
		if ((unixMode & 0004) != 0) {
			permissions.add(PosixFilePermission.OTHERS_READ);
		}
		if ((unixMode & 0002) != 0) {
			permissions.add(PosixFilePermission.OTHERS_WRITE);
		}
		if ((unixMode & 0001) != 0) {
			permissions.add(PosixFilePermission.OTHERS_EXECUTE);
		}

		return permissions;
	}
}
