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
package ghidra.file.formats.ios.generic;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class iOS_Analyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze(Program program, AddressSetView set, TaskMonitor monitor,
			final MessageLog log) throws Exception {

		DisassemblerMessageListener listener = new DisassemblerMessageListener() {
			@Override
			public void disassembleMessageReported(String msg) {
				log.appendMsg(msg);
			}
		};

		Address imageBase = program.getImageBase();

		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);

		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, listener);

		disassembler.disassemble(imageBase.add(0x00000000L), null, false);
		manager.disassemble(imageBase.add(0x00000000L));

		disassembler.disassemble(imageBase.add(0x00000004L), null, false);
		disassembler.disassemble(imageBase.add(0x00000008L), null, false);
		disassembler.disassemble(imageBase.add(0x0000000cL), null, false);
		disassembler.disassemble(imageBase.add(0x00000010L), null, false);
		disassembler.disassemble(imageBase.add(0x00000014L), null, false);
		disassembler.disassemble(imageBase.add(0x00000018L), null, false);
		disassembler.disassemble(imageBase.add(0x0000001cL), null, false);

		disassembler.disassemble(imageBase.add(0x00000020L),
			new AddressSet(imageBase.add(0x00000020L)), false);

		disassembler.disassemble(imageBase.add(0x00000040L), null, false);
		disassembler.disassemble(imageBase.add(0x00000074L), null, false);

		createData(program, imageBase.add(0x00000200L), new StringDataType());
		createData(program, imageBase.add(0x00000240L), new StringDataType());
		createData(program, imageBase.add(0x00000280L), new StringDataType());

		long offset = 0x0000032cL;
		while (!monitor.isCancelled()) {
			if (offset > 0x000005e8) {//end of ARM code...
				break;
			}
			disassembler.disassemble(imageBase.add(offset), null);
			Function function = createFunction(program, imageBase.add(offset));
			if (function == null) {
				break;
			}
			offset = function.getBody().getMaxAddress().getOffset() + 1 - imageBase.getOffset();
		}

		log.appendMsg("You should now run the iOS_ThumbFunctionFinder script!");

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
//		if ( program.getLanguage().getProcessor().equals( Processor.findOrPossiblyCreateProcessor( "ARM" ) ) ) {
//			options programInfoPropertyList = program.getPropertyList( Program.PROGRAM_INFO ) ;
//			String firmwarePath = programInfoPropertyList.getValue( "Firmware Path", (String)null );
//			if ( firmwarePath != null ) {
//				if ( firmwarePath.indexOf( "/iBoot." ) != -1 ) {
//					return true;
//				}
//				if ( firmwarePath.indexOf( "/LLB." ) != -1 ) {
//					return true;
//				}
//				if ( firmwarePath.indexOf( "/iBEC." ) != -1 ) {
//					return true;
//				}
//				if ( firmwarePath.indexOf( "/iBSS." ) != -1 ) {
//					return true;
//				}
//			}
//		}
		return false;
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public String getDescription() {
		return "Performs initial analysis for iBoot, LLB, iBSS, and iBEC files";
	}

	@Override
	public String getName() {
		return "iOS Analyzer for iBoot, LLB, iBSS, and iBEC files";
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.FORMAT_ANALYSIS;
	}

	@Override
	public boolean isPrototype() {
		return false;
	}

}
