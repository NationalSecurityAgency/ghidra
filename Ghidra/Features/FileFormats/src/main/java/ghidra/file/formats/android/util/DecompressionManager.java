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
package ghidra.file.formats.android.util;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.android.art.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DecompressionManager {

	/**
	 * Decompress the bytes and pipe into a new binary reader.
	 * Required to allow reading of the remainder of the ART header. 
	 * @param reader binary reader containing compressed bytes
	 * @param compression type of compression
	 * @param monitor task monitor for controlling the task
	 * @return binary reader containing decompressed bytes
	 * @throws IOException should an error occur reading the bytes
	 */
	public static BinaryReader decompress(BinaryReader reader, ArtCompression compression,
			TaskMonitor monitor) throws IOException {
		if (compression.getStorageMode() == ArtStorageMode.kStorageModeUncompressed) {
			return reader;//no need to decompress...
		}
		OverlayByteProvider provider = new OverlayByteProvider(reader.getByteProvider());
		BinaryReader decompressedReader = new BinaryReader(provider, reader.isLittleEndian());
		byte[] compressedBytes = reader.readByteArray(compression.getCompressedOffset(),
			compression.getCompressedSize());
		byte[] decompressedBytes = Decompressor.decompress(compression.getStorageMode(),
			compressedBytes, compression.getDecompressedSize(), monitor);
		provider.addRange(new OverlayRange(compression.getDecompressedOffset(), decompressedBytes));
		return decompressedReader;
	}

	/**
	 * Decompress the block bytes and pipe into a new binary reader.
	 * Required to allow reading of the remainder of the ART header. 
	 * @param reader binary reader containing compressed bytes
	 * @param blocks list of ART blocks that need decompressing
	 * @param monitor task monitor for controlling the task
	 * @return binary reader containing decompressed bytes
	 * @throws IOException should an error occur reading the bytes
	 */
	public static BinaryReader decompress(BinaryReader reader, List<ArtBlock> blocks,
			TaskMonitor monitor) throws IOException {
		OverlayByteProvider provider = new OverlayByteProvider(reader.getByteProvider());
		BinaryReader decompressedReader = new BinaryReader(provider, reader.isLittleEndian());
		for (ArtBlock block : blocks) {
			byte[] compressedBytes =
				reader.readByteArray(block.getDataOffset(), block.getDataSize());
			byte[] decompressedBytes = Decompressor.decompress(block.getStorageMode(),
				compressedBytes, block.getImageSize(), monitor);
			if (decompressedBytes.length != block.getImageSize()) {
				throw new RuntimeException( "decompressed length mismatch!" );
			}
			provider.addRange(new OverlayRange(block.getImageOffset(), decompressedBytes));
		}
		return decompressedReader;
	}

	/**
	 * Decompress the block bytes and lay over program memory. 
	 * @param program the program to overwrite
	 * @param blocks list of ART blocks that need decompressing
	 * @param monitor task monitor for controlling the task
	 * @throws Exception should an error occur reading the bytes
	 */
	public static void decompressOverMemory(Program program, List<ArtBlock> blocks,
			TaskMonitor monitor) throws Exception {
		for (ArtBlock block : blocks) {
			monitor.checkCanceled();

			Address sourceAddress = program.getMinAddress().add(block.getDataOffset());
			byte[] compressedBytes = new byte[block.getDataSize()];
			program.getMemory().getBytes(sourceAddress, compressedBytes);

			byte[] decompressedBytes = Decompressor.decompress(block.getStorageMode(),
				compressedBytes, block.getImageSize(), monitor);

			Address destinationAddress = program.getMinAddress().add(block.getImageOffset());

			//make sure block exists for bytes...
			AddressSet destinationSet = new AddressSet(destinationAddress,
				destinationAddress.add(decompressedBytes.length));
			AddressSet uncreatedSet = destinationSet.subtract(program.getMemory());
			for (AddressRange range : uncreatedSet) {
				monitor.checkCanceled();
				program.getMemory()
						.createInitializedBlock(toBlockName(range), range.getMinAddress(),
							range.getLength(), (byte) 0x00, monitor, false);
			}

			program.getMemory().setBytes(destinationAddress, decompressedBytes);
		}
	}

	/**
	 * Decompress the block bytes and lay over program memory. 
	 * @param program the program to overwrite
	 * @param compression type of compression
	 * @param monitor task monitor for controlling the task
	 * @throws Exception should an error occur reading the bytes
	 */
	public static void decompressOverMemory(Program program, ArtCompression compression,
			TaskMonitor monitor) throws Exception {
		if (compression.getStorageMode() != ArtStorageMode.kStorageModeUncompressed) {
			Address sourceAddress = program.getMinAddress().add(compression.getCompressedOffset());
			byte[] compressedBytes = new byte[compression.getCompressedSize()];
			program.getMemory().getBytes(sourceAddress, compressedBytes);

			byte[] decompressedBytes = Decompressor.decompress(compression.getStorageMode(),
				compressedBytes, compression.getDecompressedSize(), monitor);

			Address destinationAddress =
				program.getMinAddress().add(compression.getDecompressedOffset());

			//make block exists for bytes...
			AddressSet destinationSet = new AddressSet(destinationAddress,
				destinationAddress.add(decompressedBytes.length));
			AddressSet uncreatedSet = destinationSet.subtract(program.getMemory());
			for (AddressRange range : uncreatedSet) {
				monitor.checkCanceled();
				program.getMemory()
						.createInitializedBlock(toBlockName(range), range.getMinAddress(),
							range.getLength(), (byte) 0x00, monitor, false);
			}

			program.getMemory().setBytes(destinationAddress, decompressedBytes);
		}
	}

	private static String toBlockName(AddressRange range) {
		return "decomp_" + range.getMinAddress() + "_" + range.getMaxAddress();
	}
}
