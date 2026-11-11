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
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * 
 */
public class HCS12PPageAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "HCS12 PPAGE register setter";
	private static final String DESCRIPTION = "Sets the correct value for PPAGE reg for a whole flash area (at addresses 0x40'0000 .. 0x7F'FFFF)";

	Register ppageReg = null;
	boolean coreHCS12 = false;
	boolean coreHCS12X = false;
	
	public HCS12PPageAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		
		// run this analyzer before any code creation
		setPriority(AnalysisPriority.DISASSEMBLY.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// Only analyze HCS-12 / HCS-12X Programs
		Processor processor = program.getLanguage().getProcessor();
		coreHCS12 = "HCS-12".equals(processor.toString());
		coreHCS12X = "HCS-12X".equals(processor.toString());

		if (coreHCS12 || coreHCS12X)
		{
			ppageReg = program.getRegister("PPAGE");
			return true;
		}
		else
			return false;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// HCS12X
		// Flash Global addresses: 0x40'0000 .. 0x7F'FFFF (4MB)
		// Flash Logical addresses: 0xC000 .. 0xFFFF (16kB)
		// GlobalAddress = 0x40'0000 + (PPAGE << 14) + (LogicalAddress & 0x3FFF)
		// PPAGE max = 0xFF
		
		// HCS12
		// GlobalAddress = (PPAGE << 14) + (LogicalAddress & 0x3FFF)
		// PPAGE max = 0x3F
		
		int flashOffset = coreHCS12X ? 0x400000 : 0;
		int ppageMax = coreHCS12X ? 0xFF : 0x3F;

		for (AddressRange addrRange : set.getAddressRanges())
		{
			Address rangeStart = addrRange.getMinAddress();
			if (!rangeStart.isLoadedMemoryAddress())
				continue;
			
			for (int ppage = 0; ppage <= ppageMax; ppage++)
			{
				Address pageStart = rangeStart.getNewAddress(flashOffset + (ppage << 14));
				Address pageEnd = pageStart.add(0x3fff);
				
				AddressRange page = addrRange.intersectRange(pageStart, pageEnd);
				if (page != null)
				{
					try {
						program.getProgramContext().setValue(ppageReg, 
								page.getMinAddress(), 
								page.getMaxAddress(), 
								BigInteger.valueOf(ppage));
						
						program.getBookmarkManager().setBookmark(pageStart, BookmarkType.NOTE,
								"PPAGE setter", String.format("PPAGE set to %X", ppage));
						
					} catch (ContextChangeException e) {
						throw new AssertException(e);
					}
				}
				
			}
		}
		
		return true;
	}

}
