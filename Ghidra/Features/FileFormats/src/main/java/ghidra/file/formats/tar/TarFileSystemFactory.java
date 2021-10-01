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

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.recognizer.Bzip2Recognizer;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.UnknownProgressWrappingTaskMonitor;

public class TarFileSystemFactory implements GFileSystemFactoryByteProvider<TarFileSystem>,
		GFileSystemProbeBytesOnly, GFileSystemProbeByteProvider {

	public static final int TAR_MAGIC_BYTES_REQUIRED =
		TarConstants.VERSION_OFFSET + TarConstants.VERSIONLEN;

	private static final String[] TAR_EXTS = { ".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2" };

	@Override
	public TarFileSystem create(FSRLRoot targetFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		FSRL containerFSRL = provider.getFSRL();
		ByteProvider uncompressedBP = provider;
		if (isCompressedMagicBytes(provider)) {
			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, provider.length());
			uncompressedBP = fsService.getDerivedByteProvider(containerFSRL, null,
				"uncompressed tar", -1, () -> {
					Msg.info(TarFileSystem.class, "Uncompressing tar file " + containerFSRL);
					return newFileInputStreamAutoDetectCompressed(provider);
				}, upwtm);
			provider.close();
		}
		TarFileSystem fs = new TarFileSystem(targetFSRL, uncompressedBP, fsService);
		fs.mount(monitor);
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
	public boolean probe(ByteProvider provider, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {
		String filename = provider.getFSRL().getName();
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

		if (!isCompressedMagicBytes(provider)) {
			return false;
		}

		try (InputStream is = newFileInputStreamAutoDetectCompressed(provider)) {
			byte[] startBytes = new byte[TAR_MAGIC_BYTES_REQUIRED];
			if (is.read(startBytes) != TAR_MAGIC_BYTES_REQUIRED) {
				return false;
			}

			return probeStartBytes(provider.getFSRL(), startBytes);
		}
	}

	private static InputStream newFileInputStreamAutoDetectCompressed(ByteProvider bp)
			throws IOException {
		int magicBytes = readMagicBytes(bp);

		InputStream is = bp.getInputStream(0);
		switch (magicBytes) {
			case GZIPInputStream.GZIP_MAGIC:
				return new GZIPInputStream(is);
			case Bzip2Recognizer.MAGIC_BYTES:
				return new BZip2CompressorInputStream(is);
		}
		return is;
	}

	private static boolean isCompressedMagicBytes(ByteProvider bp) throws IOException {
		int magicBytes = readMagicBytes(bp);
		switch (magicBytes) {
			case GZIPInputStream.GZIP_MAGIC:
			case Bzip2Recognizer.MAGIC_BYTES:
				return true;
			default:
				return false;
		}
	}

	private static int readMagicBytes(ByteProvider bp) throws IOException {
		BinaryReader br = new BinaryReader(bp, true /* LE */);
		int magicBytes = br.readUnsignedShort(0);

		return magicBytes;
	}
}
