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
package ghidra.file.formats.android.dex.analyzer;

import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class DexExceptionHandlersAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws Exception {
		monitor.setMessage("DEX: exception handler markup");
		AddressSet disassembleSet = new AddressSet();
		disassembleSet.add(computeExceptionSet(program, monitor));
		DisassembleCommand dCommand = new DisassembleCommand(disassembleSet, null, true);
		dCommand.applyTo(program, monitor);
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		return DexConstants.isDexFile(provider);
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public String getDescription() {
		return "Disassembles the exception handlers in a DEX file";
	}

	@Override
	public String getName() {
		return "Android DEX Exception Handlers";
	}

	@Override
	public AnalysisPriority getPriority() {
		return new AnalysisPriority(Integer.MAX_VALUE - 1);
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

	private AddressSetView computeExceptionSet(Program program, TaskMonitor monitor)
			throws Exception {
		AddressSet set = new AddressSet();

		DexHeader header = null;

		DexAnalysisState analysisState = DexAnalysisState.getState(program);
		header = analysisState.getHeader();

		Address address = toAddr(program, DexUtil.METHOD_ADDRESS);

		for (ClassDefItem item : header.getClassDefs()) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			ClassDataItem classDataItem = item.getClassDataItem();
			if (classDataItem == null) {
				continue;
			}

			set.add(processMethods(program, address, header, item, classDataItem.getDirectMethods(),
				monitor));
			set.add(processMethods(program, address, header, item,
				classDataItem.getVirtualMethods(), monitor));
		}

		return set;
	}

	private AddressSetView processMethods(Program program, Address baseAddress, DexHeader header,
			ClassDefItem item, List<EncodedMethod> methods, TaskMonitor monitor) throws Exception {
		AddressSet set = new AddressSet();

		monitor.setMaximum(methods.size());
		monitor.setProgress(0);

		for (int i = 0; i < methods.size(); ++i) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			EncodedMethod method = methods.get(i);

			Address codeAddress = baseAddress.add(method.getCodeOffset());

			CodeItem codeItem = method.getCodeItem();
			if (codeItem == null) {
				continue;
			}

//			for ( TryItem tryItem : codeItem.getTries( ) ) {
//				monitor.checkCanceled( );
//
//				Address tryAddress = codeAddress.add( tryItem.getStartAddress( ) );
//				set.add( tryAddress );
//			}

			EncodedCatchHandlerList handlerList = codeItem.getHandlerList();
			if (handlerList == null) {
				continue;
			}

			for (EncodedCatchHandler handler : handlerList.getHandlers()) {
				monitor.checkCanceled();

				List<EncodedTypeAddressPair> pairs = handler.getPairs();
				for (EncodedTypeAddressPair pair : pairs) {
					monitor.checkCanceled();

					int catchTypeIndex = pair.getTypeIndex();
					TypeIDItem catchTypeIDItem = header.getTypes().get(catchTypeIndex);
					StringIDItem catchStringItem =
						header.getStrings().get(catchTypeIDItem.getDescriptorIndex());
					String catchString = catchStringItem.getStringDataItem().getString();
					Address catchAddress = codeAddress.add(pair.getAddress() * 2);

					createCatchSymbol(program, catchString, catchAddress);
					set.add(catchAddress);
				}

				if (handler.getSize() <= 0) {
					Address catchAllAddress = codeAddress.add(handler.getCatchAllAddress() * 2);
					createCatchSymbol(program, "CatchAll", catchAllAddress);
					set.add(catchAllAddress);
				}
			}
		}

		return set;
	}

	private void createCatchSymbol(Program program, String catchName, Address catchAddress) {
		Namespace catchNameSpace = DexUtil.getOrCreateNameSpace(program, "CatchHandlers");
		try {
			program.getSymbolTable().createLabel(catchAddress, catchName, catchNameSpace,
				SourceType.ANALYSIS);
		}
		catch (Exception e) {
			Msg.error(this, "Error creating label", e);
		}
	}

}
