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
package sarif.managers;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import generic.stl.Pair;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.SarifUtils;
import sarif.export.SarifWriterTask;
import sarif.export.mm.SarifMemoryMapWriter;

public class MemoryMapSarifMgr extends SarifMgr {

	public static String KEY = "MEMORY_MAP";
	public static String SUBKEY = "MemorySection";

	private ProgramSarifMgr programMgr;

	private MemoryMapBytesFile bf;

	MemoryMapSarifMgr(ProgramSarifMgr programMgr, Program program, MessageLog log) {
		super(KEY, program, log);
		this.programMgr = programMgr;
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options,
			TaskMonitor monitor) throws CancelledException {
		try {
			processMemoryBlock(result, programMgr.getDirectory(), program, monitor);
			return true;
		}
		catch (FileNotFoundException | AddressOverflowException e) {
			log.appendException(e);
		}
		return false;
	}

	private void processMemoryBlock(Map<String, Object> result, String directory, Program program,
			TaskMonitor monitor) throws FileNotFoundException, AddressOverflowException {

		String name = (String) result.get("name");
		AddressSet set = SarifUtils.getLocations(result, program, null);
		Address blockAddress = set.getMinAddress();
		if (set.getNumAddressRanges() != 1) {
			throw new RuntimeException("Unexpected number of ranges for block @ " + blockAddress +
				": " + set.getNumAddressRanges());
		}
		int length = (int) set.getMaxAddress().subtract(blockAddress) + 1;

		String permissions = (String) result.get("kind");
		if (permissions == null) {
			permissions = "r";
		}
		boolean r = permissions.indexOf("r") >= 0;
		boolean w = permissions.indexOf("w") >= 0;
		boolean x = permissions.indexOf("x") >= 0;

		boolean isVolatile = (boolean) result.get("isVolatile");
		boolean isArtificial = (boolean) result.get("isArtificial");

		String comment = (String) result.get("comment");
		String type = (String) result.get("type");
		String loc = (String) result.get("location"); // location == position of the bytes w/i file (file::pos)
		// TODO: Explore the possibility of using FileBytes in the future?

		try {
			MemoryBlock block = null;
			if (type.equals("DEFAULT")) {
				if (loc == null) {
					block = MemoryBlockUtils.createUninitializedBlock(program, false, name,
						blockAddress, length, comment, null, r, w, x, log);
				}
				else {
					String[] split = loc.split(":");
					String fileName = split[0];
					int fileOffset = Integer.parseInt(split[1]);
					byte[] bytes = setData(directory, fileName, fileOffset, length, log);
					block = MemoryBlockUtils.createInitializedBlock(program, false, name,
						blockAddress, new ByteArrayInputStream(bytes), bytes.length, comment, null,
						r, w, x, log, monitor);
				}
			}
			else if (type.equals("BIT_MAPPED")) {
				Address sourceAddr = factory.getAddress(loc);
				block = MemoryBlockUtils.createBitMappedBlock(program, name, blockAddress,
					sourceAddr, length, comment, comment, r, w, x, false, log);
			}
			else if (type.equals("BYTE_MAPPED")) {
				Address sourceAddr = factory.getAddress(loc);
				block = MemoryBlockUtils.createByteMappedBlock(program, name, blockAddress,
					sourceAddr, length, comment, comment, r, w, x, false, log);
			}
			else {
				throw new RuntimeException("Unexpected type value - " + type);
			}
			if (block != null) {
				block.setVolatile(isVolatile);
				block.setArtificial(isArtificial);
			}
		}
		catch (FileNotFoundException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private byte[] setData(String directory, String fileName, int fileOffset, int length,
			MessageLog log) throws IOException {
		byte[] bytes = new byte[length];
		Arrays.fill(bytes, (byte) 0xff);
		File f = new File(directory, fileName);
		try (RandomAccessFile binfile = new RandomAccessFile(f, "r")) {
			int pos = 0;
			while (pos < length) {
				int readLen = (512 * 1024);
				if ((readLen + pos) > length) {
					readLen = length - pos;
				}
				binfile.seek(fileOffset + pos);
				readLen = binfile.read(bytes, pos, readLen);
				if (readLen <= 0) {
					break;
				}
				pos += readLen;
			}
		}
		catch (IndexOutOfBoundsException e) {
			log.appendMsg("Read exceeded array length " + length);
		}
		return bytes;
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView addrs, TaskMonitor monitor,
			boolean isWriteContents, String filePath) throws IOException, CancelledException {
		monitor.setMessage("Writing MEMORY MAP ...");

		List<Pair<AddressRange, MemoryBlock>> request = new ArrayList<>();
		AddressRangeIterator iter = addrs.getAddressRanges();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			AddressRange ranges = iter.next();
			RangeBlock rb =
				new RangeBlock(program.getAddressFactory(), program.getMemory(), ranges);
			for (int i = 0; i < rb.getRanges().length; ++i) {
				AddressRange range = rb.getRanges()[i];
				MemoryBlock block = rb.getBlocks()[i];
				request.add(new Pair<AddressRange, MemoryBlock>(range, block));
			}
		}

		try {
			bf = isWriteContents ? new MemoryMapBytesFile(program, filePath) : null;
			writeAsSARIF(request, bf, isWriteContents, results);
		}
		finally {
			if (isWriteContents) {
				bf.close();
			}
		}
	}

	public static void writeAsSARIF(List<Pair<AddressRange, MemoryBlock>> request,
			MemoryMapBytesFile bytes, boolean isWriteContents, JsonArray results)
			throws IOException {
		SarifMemoryMapWriter writer =
			new SarifMemoryMapWriter(request, null, bytes, isWriteContents);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}

class RangeBlock {
	private ArrayList<AddressRange> rangeList = new ArrayList<>();
	private ArrayList<MemoryBlock> blockList = new ArrayList<>();

	RangeBlock(AddressFactory af, Memory memory, AddressRange range) {
		AddressSet set = new AddressSet(range);
		while (!set.isEmpty()) {
			MemoryBlock block = memory.getBlock(set.getMinAddress());
			set.deleteRange(block.getStart(), block.getEnd());
			rangeList.add(range.intersect(new AddressRangeImpl(block.getStart(), block.getEnd())));
			blockList.add(block);
		}
	}

	AddressRange[] getRanges() {
		AddressRange[] ranges = new AddressRange[rangeList.size()];
		rangeList.toArray(ranges);
		return ranges;
	}

	MemoryBlock[] getBlocks() {
		MemoryBlock[] blocks = new MemoryBlock[rangeList.size()];
		blockList.toArray(blocks);
		return blocks;
	}
}
