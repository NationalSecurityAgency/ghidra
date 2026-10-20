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
package ghidra.file.formats.yaffs2;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider;
import ghidra.program.model.lang.Endian;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class YAFFS2FileSystemFactory
		implements GFileSystemFactoryByteProvider<YAFFS2FileSystem>, GFileSystemProbeByteProvider {

	private static final int MIN_REQUIRED_OBJHDRS = 2;
	private static final int MAX_OBJHDRS_TO_CHECK = 5;

	@Override
	public boolean probe(ByteProvider byteProvider, FileSystemService fsService,
			TaskMonitor monitor) throws IOException, CancelledException {
		return hasObjHeaders(byteProvider, 2048, 64, true);
	}

	/**
	 * Returns true if the stream appears to have a few valid yaffs2 obj_hdr structs at the start.
	 *  
	 * @param bp {@link ByteProvider} stream
	 * @param pageSize typically 2048
	 * @param oobSize only tested with 64 byte 
	 * @param isLE only tested with LE
	 * @return boolean true if it appears to be a valid YAFFS2 image
	 * @throws IOException if error reading
	 */
	boolean hasObjHeaders(ByteProvider bp, int pageSize, int oobSize, boolean isLE)
			throws IOException {
		BinaryReader br = new BinaryReader(bp, isLE);
		long stride = pageSize + oobSize;
		int pageCount = (int) (bp.length() / stride);
		int foundCount = 0;
		for (int pageNum = 0; pageNum < pageCount && foundCount < MAX_OBJHDRS_TO_CHECK; pageNum++) {
			br.setPointerIndex(pageNum * stride);
			YAFFS2Header hdr = YAFFS2Header.read(br);
			if (!hdr.isValid(bp)) {
				return false;
			}
			pageNum += hdr.getDataPageCount(pageSize);
			foundCount++;
		}
		return foundCount > MIN_REQUIRED_OBJHDRS;
	}

	@Override
	public GFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
			FileSystemService fsService, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			YAFFS2FileSystem fs =
				new YAFFS2FileSystem(byteProvider, 2048, 64, Endian.LITTLE, targetFSRL, fsService);
			fs.mount(monitor);

			return fs;
		}
		catch (IOException | CancelledException e) {
			FSUtilities.uncheckedClose(byteProvider, null);
			return null;
		}
	}

}
