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
import java.util.Set;
import java.util.zip.GZIPInputStream;

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarConstants;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.tukaani.xz.XZ;

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

	private static final Set<String> TAR_EXTS =
		Set.of(".tar", ".tgz", ".tar.gz", ".tbz2", ".tar.bz2", ".tar.xz");


	@Override
	public TarFileSystem create(FSRLRoot targetFSRL, ByteProvider provider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {

		FSRL containerFSRL = provider.getFSRL();
		ByteProvider uncompressedBP = provider;
		TarCompressors compressor = detectCompressor(provider);
		if (compressor != null) {
			UnknownProgressWrappingTaskMonitor upwtm =
				new UnknownProgressWrappingTaskMonitor(monitor, provider.length());
			uncompressedBP = fsService.getDerivedByteProvider(containerFSRL, null,
				"uncompressed tar", -1, () -> {
					Msg.info(TarFileSystem.class, "Uncompressing tar file " + containerFSRL);
					return getTarInputStream(provider, compressor);
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
	 * a {@link GZipFileSystem} (and friends) has exposed the uncompressed data.
	 *
	 */
	@Override
	public boolean probe(ByteProvider provider, FileSystemService fsService,
			TaskMonitor taskMonitor) throws IOException, CancelledException {
		if (!hasTarExt(provider.getFSRL().getName().toLowerCase())) {
			return false;
		}

		try (InputStream is = getTarInputStream(provider, detectCompressor(provider))) {
			byte[] startBytes = new byte[TAR_MAGIC_BYTES_REQUIRED];
			if (is.read(startBytes) != TAR_MAGIC_BYTES_REQUIRED) {
				return false;
			}

			return probeStartBytes(provider.getFSRL(), startBytes);
		}
	}

	private static InputStream getTarInputStream(ByteProvider bp, TarCompressors compressor)
			throws IOException {

		InputStream is = bp.getInputStream(0);
		return switch (compressor) {
			case null -> is;
			case GZIP -> new GZIPInputStream(is);
			case BZIP2 -> new BZip2CompressorInputStream(is);
			case XZ -> new XZCompressorInputStream(is);
		};
	}


	private static TarCompressors detectCompressor(ByteProvider bp) throws IOException {
		int magicBytes = readMagicShort(bp);
		switch (magicBytes) {
			case GZIPInputStream.GZIP_MAGIC:
				return TarCompressors.GZIP;
			case Bzip2Recognizer.MAGIC_BYTES:
				return TarCompressors.BZIP2;
		}

		byte[] startBytes = bp.readBytes(0, XZ.HEADER_MAGIC.length);
		if (XZCompressorInputStream.matches(startBytes, startBytes.length)) {
			return TarCompressors.XZ;
		}

		return null;
	}

	private static int readMagicShort(ByteProvider bp) throws IOException {
		BinaryReader br = new BinaryReader(bp, true /* LE */);
		int magicBytes = br.readUnsignedShort(0);

		return magicBytes;
	}

	private static boolean hasTarExt(String filename) {
		for (String ext : TAR_EXTS) {
			if (filename.endsWith(ext)) {
				return true;
			}
		}
		return false;
	}

	enum TarCompressors { GZIP, BZIP2, XZ }
}
