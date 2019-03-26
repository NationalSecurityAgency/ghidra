/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//Splits a Mac OS X Universal Binary into the separate
//files for each processor. The output files
//are placed in the same directory with the processor name appended.
//@category Binary

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.app.util.bin.format.ubi.FatArch;
import ghidra.app.util.bin.format.ubi.FatHeader;
import ghidra.program.model.lang.Processor;

import java.io.*;
import java.util.List;


public class SplitUniversalBinariesScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File ubiFile = askFile("Select Universal Binary File", "C'mon, Do it! Push da bahtahn!");
		File outputDirectory = askDirectory("Select Output Directory", "GO");

		ByteProvider provider = new RandomAccessByteProvider(ubiFile) ;
		FatHeader header = FatHeader.createFatHeader(RethrowContinuesFactory.INSTANCE, provider);

		List<FatArch> architectures = header.getArchitectures();
		for (FatArch arch : architectures) {
			int offset = arch.getOffset();
			int   size = arch.getSize();

			Processor processor = CpuTypes.getProcessor(arch.getCpuType(), arch.getCpuSubType());
			int processorSize = CpuTypes.getProcessorBitSize(arch.getCpuType());

			File outFile = new File(outputDirectory, ubiFile.getName()+"."+processor+"."+processorSize);
			OutputStream out = new FileOutputStream(outFile);
			try {
				for (int i = offset ; i < offset+size ; i+=4096) {
					if (i + 4096 < offset+size) {
						out.write(provider.readBytes(i, 4096));
					}
					else {
						out.write(provider.readBytes(i, offset+size-i));
					}
				}
			}
			finally {
				out.close();
			}
		}
	}
}
