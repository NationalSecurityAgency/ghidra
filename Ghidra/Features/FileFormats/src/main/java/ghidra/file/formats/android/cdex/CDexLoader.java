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
package ghidra.file.formats.android.cdex;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class CDexLoader extends DexLoader {

	@Override
	public String getName() {
		return CDexConstants.NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.UNTARGETED_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		try {
			byte[] magicBytes = provider.readBytes(0, CDexConstants.MAGIC.length());
			if (CDexConstants.MAGIC.equals(new String(magicBytes))) {
				DexHeader header = DexHeaderFactory.getDexHeader(reader);//should be CDEX
				if (CDexConstants.MAGIC.equals(new String(header.getMagic()))) {
					List<QueryResult> queries =
						QueryOpinionService.query(getName(), DexConstants.MACHINE, null);
					for (QueryResult result : queries) {
						loadSpecs.add(new LoadSpec(this, 0, result));
					}
					if (loadSpecs.isEmpty()) {
						loadSpecs.add(new LoadSpec(this, 0, true));
					}
				}
			}
		}
		catch (Exception e) {
			//ignore
		}
		return loadSpecs;
	}

	@Override
	public boolean supportsLoadIntoProgram() {
		return true;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage("CDEX Loader: creating cdex memory");
		try {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
			long length = provider.length();

			try (InputStream inputStream = provider.getInputStream(0)) {
				program.getMemory()
						.createInitializedBlock(".cdex", start, inputStream, length, monitor,
							false);
			}

			BinaryReader reader = new BinaryReader(provider, true);
			DexHeader header = DexHeaderFactory.getDexHeader(reader);

			monitor.setMessage("CDEX Loader: creating method byte code");

			createMethodLookupMemoryBlock(program, monitor);
			createMethodByteCodeBlock(program, length, monitor);

			for (ClassDefItem item : header.getClassDefs()) {
				monitor.checkCanceled();

				ClassDataItem classDataItem = item.getClassDataItem();
				if (classDataItem == null) {
					continue;
				}

				createMethods(program, header, item, classDataItem.getDirectMethods(), monitor,
					log);
				createMethods(program, header, item, classDataItem.getVirtualMethods(), monitor,
					log);
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor)
			throws Exception {
		Address address = toAddr(program, DexUtil.METHOD_ADDRESS);
		MemoryBlock block = program.getMemory()
				.createInitializedBlock("method_bytecode", address, length, (byte) 0xff, monitor,
					false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
	}

	private void createMethodLookupMemoryBlock(Program program, TaskMonitor monitor)
			throws Exception {
		Address address = toAddr(program, DexUtil.LOOKUP_ADDRESS);
		MemoryBlock block = program.getMemory()
				.createInitializedBlock("method_lookup", address, DexUtil.MAX_METHOD_LENGTH,
					(byte) 0xff, monitor, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
	}

	private void createMethods(Program program, DexHeader header, ClassDefItem item,
			List<EncodedMethod> methods, TaskMonitor monitor, MessageLog log) throws Exception {
		for (int i = 0; i < methods.size(); ++i) {
			monitor.checkCanceled();

			EncodedMethod encodedMethod = methods.get(i);

			CodeItem codeItem = encodedMethod.getCodeItem();

			Address methodIndexAddress =
				DexUtil.toLookupAddress(program, encodedMethod.getMethodIndex());

			if (codeItem == null) {
				//external method, ignore
			}
			else {
				Address methodAddress =
					toAddr(program, DexUtil.METHOD_ADDRESS + encodedMethod.getCodeOffset());

				byte[] instructionBytes = codeItem.getInstructionBytes();
				program.getMemory().setBytes(methodAddress, instructionBytes);

				program.getMemory().setInt(methodIndexAddress, (int) methodAddress.getOffset());
			}
		}
	}

	private Address toAddr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

}
