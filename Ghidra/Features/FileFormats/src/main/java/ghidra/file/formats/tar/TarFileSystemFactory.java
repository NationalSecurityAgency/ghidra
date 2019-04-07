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
package ghidra.file.formats.tar;

import java.io.*;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.recognizer.Bzip2Recognizer;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

public class TarFileSystemFactory implements GFileSystemFactoryWithFile<TarFileSystem>,
		GFileSystemProbeBytesOnly, GFileSystemProbeWithFile {

	public static final int TAR_MAGIC_BYTES_REQUIRED =
		TarConstants.VERSION_OFFSET + TarConstants.VERSIONLEN;

	private static final String[] TAR_EXTS = { ".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2" };

	@Override
	public TarFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL, File containerFile,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (isCompressedTarFile(containerFile)) {
			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, containerFile.length());
			FileCacheEntry fce =
				fsService.getDerivedFile(containerFSRL, "uncompressed tar", (srcFile) -> {
					Msg.info(TarFileSystem.class, "Uncompressing tar file " + containerFSRL);
					return newFileInputStreamAutoDetectCompressed(srcFile);
				}, upwtm);
			containerFile = fce.file;
		}
		TarFileSystem fs = new TarFileSystem(containerFile, targetFSRL, fsService);
		fs.mount(false, monitor);
		return fs;
	}

	@Override
	public int getBytesRequired() {
		return TAR_MAGIC_BYTES_REQUIRED;
	}

	@Override
	public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
		return TarArchiveInputStream.matches(startBytes, startBytes.length);
	}

	/*
	 * Recognize compressed TAR files, only if they have a well known filename extension.
	 * <p>
	 * Note: if a compressed TAR file doesn't have a well-known extension, the
	 * other {@link #probeStartBytes(FSRL, byte[]) probe method} will detect the TAR file after
	 * the {@link GZipFileSystem} has exposed the uncompressed data.
	 *
	 */
	@Override
	public boolean probe(FSRL containerFSRL, File containerFile, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {
		String filename = containerFSRL.getName();
		String ext = FSUtilities.getExtension(filename, 1);
		if (ext == null) {
			return false;
		}
		ext = ext.toLowerCase();

		// special case hack to get 2-part ext for tar.gz or tar.bz2
		ext =
			(".gz".equals(ext) || ".bz2".equals(ext)) ? FSUtilities.getExtension(filename, 2) : ext;

		// Only continue with probe (which requires us to open the file) if it has the
		// correct file extension.'
		if (!ArrayUtils.contains(TAR_EXTS, ext)) {
			return false;
		}

		try (InputStream is = newFileInputStreamAutoDetectCompressed(containerFile)) {
			byte[] startBytes = new byte[TAR_MAGIC_BYTES_REQUIRED];
			if (is.read(startBytes) != TAR_MAGIC_BYTES_REQUIRED) {
				return false;
			}

			return probeStartBytes(null, startBytes);
		}
	}

	private static int readUShort(InputStream in) throws IOException {
		byte[] buf = new byte[2];
		if (in.read(buf) != 2) {
			throw new IOException("Not enough bytes to read short");
		}
		return ((buf[1] & 0xff) << 8) | (buf[0] & 0xff);
	}

	private static InputStream newFileInputStreamAutoDetectCompressed(File f) throws IOException {
		InputStream is = new BufferedInputStream(new FileInputStream(f));
		is.mark(2);
		int magicbytes = readUShort(is);
		is.reset();
		switch (magicbytes) {
			case GZIPInputStream.GZIP_MAGIC:
				is = new GZIPInputStream(is);
				break;
			case Bzip2Recognizer.MAGIC_BYTES:
				is = new BZip2CompressorInputStream(is);
				break;
		}
		return is;
	}

	private static boolean isCompressedStream(InputStream is) {
		// this needs to match the implementation details of the newFileInputStreamAutoDetectCompressed() func just a few lines above.
		return (is instanceof GZIPInputStream) || (is instanceof BZip2CompressorInputStream);
	}

	private static boolean isCompressedTarFile(File f) throws IOException {
		try (InputStream is = newFileInputStreamAutoDetectCompressed(f)) {
			return isCompressedStream(is);
		}
	}
}
