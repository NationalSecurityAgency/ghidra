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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DexLoader extends AbstractProgramWrapperLoader {

	public DexLoader() {
	}

	@Override
	public String getName() {
		return "Dalvik Executable (DEX)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		try {
			DexHeader header = DexHeaderFactory.getDexHeader(reader);
			if (DexConstants.DEX_MAGIC_BASE.equals(new String(header.getMagic()))) {
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
		catch (Exception e) {
			//ignore
		}

		return loadSpecs;
	}

	@Override
	public void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage(getMonitorMessagePrimary());
		try {
			Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
			long length = provider.length();

			try (InputStream inputStream = provider.getInputStream(0)) {
				program.getMemory()
						.createInitializedBlock(getMemoryBlockName(), start, inputStream, length,
							monitor, false);
			}

			BinaryReader reader = new BinaryReader(provider, true);
			DexHeader header = DexHeaderFactory.getDexHeader(reader);

			monitor.setMessage(getMonitorMessageSecondary());

			createMethodLookupMemoryBlock(program, monitor);
			createMethodByteCodeBlock(program, length, monitor);

			for (ClassDefItem item : header.getClassDefs()) {
				monitor.checkCancelled();

				ClassDataItem classDataItem = item.getClassDataItem();
				if (classDataItem == null) {
					continue;
				}

				createMethods(program, header, item, classDataItem.getDirectMethods(), monitor,
					log);
				createMethods(program, header, item, classDataItem.getVirtualMethods(), monitor,
					log);
			}

			markupMethodLookup(program, header, monitor, log);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	protected void createMethodByteCodeBlock(Program program, long length, TaskMonitor monitor)
			throws Exception {
		Address address = toAddr(program, DexUtil.METHOD_ADDRESS);
		MemoryBlock block = program.getMemory()
				.createInitializedBlock("method_bytecode", address, length, (byte) 0xff, monitor,
					false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
	}

	protected void createMethodLookupMemoryBlock(Program program, TaskMonitor monitor)
			throws Exception {
		Address address = toAddr(program, DexUtil.LOOKUP_ADDRESS);
		MemoryBlock block = program.getMemory()
				.createInitializedBlock("method_lookup", address, DexUtil.MAX_METHOD_LENGTH,
					(byte) 0xff, monitor, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
	}

	protected void createMethods(Program program, DexHeader header, ClassDefItem item,
			List<EncodedMethod> methods, TaskMonitor monitor, MessageLog log) throws Exception {
		for (int i = 0; i < methods.size(); ++i) {
			monitor.checkCancelled();

			EncodedMethod encodedMethod = methods.get(i);

			CodeItem codeItem = encodedMethod.getCodeItem();

			Address methodIndexAddress =
				DexUtil.toLookupAddress(program, encodedMethod.getMethodIndex());

			if (codeItem == null) {
				//external method
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

	protected void markupMethodLookup(Program program, DexHeader header, TaskMonitor monitor,
			MessageLog log)
			throws Exception {

		monitor.setMessage("DEX: processing methods");
		monitor.setMaximum(header.getMethodIdsSize());
		monitor.setProgress(0);

		int methodIndex = 0;
		for (MethodIDItem item : header.getMethods()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);

			StringBuilder builder = new StringBuilder();
			builder.append("Method Index: 0x" + Integer.toHexString(methodIndex) + "\n");
			builder.append(
				"Class: " + DexUtil.convertTypeIndexToString(header, item.getClassIndex()) + "\n");
			builder.append("Prototype: " +
				DexUtil.convertPrototypeIndexToString(header, item.getProtoIndex()) + "\n");
			builder.append("Name: " + DexUtil.convertToString(header, item.getNameIndex()) + "\n");

			Address methodIndexAddress = DexUtil.toLookupAddress(program, methodIndex);

			if (program.getMemory().getInt(methodIndexAddress) == -1) {
				program.getListing()
						.setComment(methodIndexAddress, CodeUnit.PLATE_COMMENT, builder.toString());

				// Add placeholder symbol for external functions
				String methodName = DexUtil.convertToString(header, item.getNameIndex());
				String className = DexUtil.convertTypeIndexToString(header, item.getClassIndex());
				Namespace classNameSpace =
					DexUtil.createNameSpaceFromMangledClassName(program, className);
				if (classNameSpace != null) {
					Address externalAddress = DexUtil.toLookupAddress(program, methodIndex);
					Symbol methodSymbol =
						createMethodSymbol(program, externalAddress, methodName, classNameSpace,
							log);
					if (methodSymbol != null) {
						String externalName = methodSymbol.getName(true);
						program.getReferenceManager()
								.addExternalReference(methodIndexAddress,
									"EXTERNAL.dex-" + methodIndex, externalName, null,
									SourceType.ANALYSIS, 0, RefType.DATA);
					}
				}
			}
			program.getListing().createData(methodIndexAddress, new PointerDataType());

			++methodIndex;
		}
	}

	private Symbol createMethodSymbol(Program program, Address methodAddress, String methodName,
			Namespace classNameSpace, MessageLog log) {

		program.getSymbolTable().addExternalEntryPoint(methodAddress);
		try {
			return program.getSymbolTable()
					.createLabel(methodAddress, methodName, classNameSpace, SourceType.ANALYSIS);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
			return null;
		}
	}

	protected Address toAddr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected String getMemoryBlockName() {
		return ".dex";
	}

	protected String getMonitorMessagePrimary() {
		return "DEX Loader: creating dex memory";
	}

	protected String getMonitorMessageSecondary() {
		return "DEX Loader: creating method byte code";
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean loadIntoProgram) {

		return Collections.emptyList();
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		return null;
	}
}
