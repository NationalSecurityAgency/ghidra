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
//Splits an Extensible Firmware Interface (EFI) binary into the separate
//MZ/PE files for each processor. 
//The output files are placed in the selected directory with the processor name appended.
//@category Binary

import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.macho.CpuTypes;
import ghidra.program.model.lang.Processor;

public class SplitExtensibleFirmwareInterfaceScript extends GhidraScript {

	public final static int MAGIC = 0x0ef1fab9;

	@Override
	public void run() throws Exception {

		StringBuffer messages = new StringBuffer();

		File efiFile = askFile("Select EFI File", "EFI");

		File directory = askDirectory("Select Output Directory for Parsed EFI", "OK");

		ByteProvider provider = new RandomAccessByteProvider(efiFile);
		try {
			BinaryReader reader = new BinaryReader(provider, true);

			int magic = reader.readNextInt();

			if (magic != MAGIC) {
				popup("THIS DOES NOT APPEAR TO BE A VALID APPLE EFI FILE");
				return;
			}

			int architecturesCount = reader.readNextInt();

			monitor.setMaximum(architecturesCount);

			for (int i = 0; i < architecturesCount; ++i) {

				monitor.setProgress(i);

				if (monitor.isCancelled()) {
					break;
				}

				int cpuType = reader.readNextInt();
				int cpuSubType = reader.readNextInt();
				int offset = reader.readNextInt();
				int size = reader.readNextInt();
				int alignment = reader.readNextInt();

				Processor processor = CpuTypes.getProcessor(cpuType, cpuSubType);
				int processorBitSize = CpuTypes.getProcessorBitSize(cpuType);
				String processorString = processor + "-" + processorBitSize + "-bit";
				String targetName =
					efiFile.getName() + "_" + processorString + "_" + "at" + "_" + "0x" +
						Integer.toHexString(offset);

				String message =
					"EFI Target found: " + processorString + " at 0x" +
						Integer.toHexString(offset) + " with alignment " + alignment;
				monitor.setMessage(message);
				messages.append(message + "\n");
				println(message);

				byte[] targetBytes = reader.readByteArray(offset, size);

				OutputStream targetOut = new FileOutputStream(new File(directory, targetName));
				try {
					targetOut.write(targetBytes);
				}
				finally {
					targetOut.close();
				}
			}

			popup(messages.toString());
		}
		finally {
			provider.close();
		}
	}

}
