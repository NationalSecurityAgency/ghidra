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
// This script displays data about Microsoft development tools (compilers, linkers, etc.) 
// used to build objects within program as stored in the Rich header and table.
//
//@category Windows
//@keybinding 
//@menupath 
//@toolbar 
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.RichHeader;
import ghidra.app.util.bin.format.pe.rich.*;
import ghidra.util.Conv;

public class PortableExecutableRichPrintScript extends GhidraScript {

	private static int LINKER_VERSION_5_PRODUCTID = 0x0014;

	@Override
	public void run() throws Exception {

		ByteProvider provider =
			new MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase());

		PortableExecutable pe = null;

		try {
			pe = PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE,
				provider, SectionLayout.MEMORY, false, false);
		}
		catch (Exception e) {
			printerr("Unable to create PE from current program");
			provider.close();
			return;
		}

		RichHeader rich = pe.getRichHeader();
		if (rich == null || rich.getSize() == 0) {
			print("Rich Header not found");
			provider.close();
			return;
		}

		provider.close();

		String format = "%6s %10s %14s %16s %-16s %s\n";
		printf(format, "Index", "@comp.id", "Ref. Count", "Product Code", "Type", "Description");

		for (RichHeaderRecord record : rich.getRecords()) {

			CompId compid = record.getCompId();

			RichProduct prod = RichHeaderUtils.getProduct(compid.getProductId());

			StringBuilder sb = new StringBuilder();

			String prodVersion = prod == null
					? "Unknown Product (" + Integer.toHexString(compid.getProductId()) + ")"
					: prod.getProductVersion();
			MSProductType prodType = prod == null ? MSProductType.Unknown : prod.getProductType();

			if (prodType != MSProductType.Unknown) {
				sb.append(prodType).append(" from ").append(prodVersion).append(", build ").append(
					compid.getBuildNumber());
			}
			else {
				sb.append(prodVersion);
			}

			printf(format, record.getIndex(), Integer.toHexString(compid.getValue()),
				record.getObjectCount(), Integer.toHexString(compid.getProductId()), prodType,
				sb.toString());
		}

		try {
			verifyChecksum(provider, pe);

		}
		finally {
			provider.close();
		}

	}

	private boolean verifyChecksum(ByteProvider provider, PortableExecutable pe)
			throws IOException {

		RichHeader rich = pe.getRichHeader();
		if (rich == null) {
			return true;
		}

		int checksum = computeChecksum(provider, pe);

		if (checksum != rich.getMask()) {
			printf("\nComputed checksum and table mask differ -- 0x%08x vs 0x%08x\n", checksum,
				rich.getMask());
			return false;
		}
		return true;
	}

	private static int rol32(int value, int bits) {
		return (value << bits) | (value >> 32 - bits);
	}

	private static int computeChecksum(ByteProvider provider, PortableExecutable pe)
			throws IOException {

		RichHeader rich = pe.getRichHeader();

		int checksum = rich.getOffset();

		// Linker version 5 has a product ID of 0x14 and was the last version to use a slightly 
		// different checksumming algorithm; after v5, the DOS program was also included
		// in the checksum range.		

		int dosChecksum = checksumDosHeader(provider,
			isToolchainVersionAfterV5(rich) ? pe.getDOSHeader().getProgramLen() : 0);

		checksum += dosChecksum;

		for (RichHeaderRecord record : rich.getRecords()) {
			checksum += rol32(record.getCompId().getValue(), record.getObjectCount() & 0xFF);
		}
		return checksum;
	}

	private static boolean isToolchainVersionAfterV5(RichHeader rich) {

		// @formatter:off
		long version5OrGreater = Arrays.stream(rich.getRecords())
				.map(r -> r.getCompId().getProductId())
				.filter(id -> id > LINKER_VERSION_5_PRODUCTID)
				.collect(Collectors.counting());		
		// @formatter:on
		
		return version5OrGreater != 0;
	}

	private static int checksumDosHeader(ByteProvider provider, int programLength)
			throws IOException {

		int checksum = 0;

		byte[] data = provider.readBytes(0, DOSHeader.SIZEOF_DOS_HEADER + programLength);
		// blank out the PE offset, 'e_lfanew'
		data[0x3c] = 0;
		data[0x3d] = 0;

		for (int i = 0; i < DOSHeader.SIZEOF_DOS_HEADER + programLength; i++) {
			int b = data[i] & Conv.BYTE_MASK;
			checksum += rol32(b, (i & 0x1f));
		}
		return checksum;

	}

}
