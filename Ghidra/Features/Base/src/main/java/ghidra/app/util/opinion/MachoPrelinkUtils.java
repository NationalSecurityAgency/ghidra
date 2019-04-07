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
import java.util.*;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.jdom.JDOMException;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.SegmentCommand;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.app.util.bin.format.macho.prelink.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Utilities methods for working with Mach-O PRELINK binaries.
 */
public class MachoPrelinkUtils {

	/**
	 * Parses the provider looking for PRELINK XML.
	 * 
	 * @param provider The provider to parse.
	 * @param monitor A monitor.
	 * @return A list of discovered {@link PrelinkMap}s.  An empty list indicates that the provider
	 *   did not represent valid Mach-O PRELINK binary.
	 * @throws IOException if there was an IO-related issue.
	 * @throws JDOMException if there was a issue parsing the PRELINK XML.
	 */
	public static List<PrelinkMap> parsePrelinkXml(ByteProvider provider, TaskMonitor monitor)
			throws IOException, JDOMException {

		try {
			MachHeader mainHeader =
				MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider);
			mainHeader.parse(); // make sure first Mach-O header is valid....

			monitor.setMessage("Parsing PRELINK XML...");
			return new PrelinkParser(mainHeader, provider).parse(monitor);
		}
		catch (NoPreLinkSectionException | MachException e) {
			return Collections.emptyList();
		}
	}

	/**
	 * Scans the provider looking for PRELINK Mach-O headers.  
	 * <p>
	 * NOTE: The "System" Mach-O at offset 0 is not considered a PRELINK Mach-O.
	 * <p>
	 * NOTE: We used to scan on 0x1000, and then 0x10 byte boundaries.  Now iOS 12 seems to 
	 * put them on 0x8-byte boundaries.
	 * 
	 * @param provider The provider to scan.
	 * @param monitor A monitor.
	 * @return A list of provider offsets where PRELINK Mach-O headers start (not including the
	 *   "System" Mach-O at offset 0).
	 * @throws IOException If there was an IO-related issue searching for PRELINK Mach-O headers.
	 */
	public static List<Long> findPrelinkMachoHeaderOffsets(ByteProvider provider,
			TaskMonitor monitor) throws IOException {
		monitor.setMessage("Finding PRELINK Mach-O headers...");
		monitor.initialize((int) provider.length());

		List<Long> list = new ArrayList<>(); // This list must maintain ordering...don't sort it		
		for (long offset = 0; offset < provider.length() - 4; offset += 8) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress((int) offset);

			if (getMachoLoadSpec(provider, offset) != null) {
				if (offset > 0) {
					// Don't put first "System" Mach-O in list
					list.add(offset);
				}
			}
			else if (offset == 0) {
				// if it doesn't start with a Mach-O, just quit
				break;
			}
		}
		return list;
	}

	/**
	 * Forms a bidirectional mapping of PRELINK XML to Mach-O header offset in the given provider.
	 * 
	 * @param provider The PRELINK Mach-O provider.
	 * @param prelinkList A list of {@link PrelinkMap}s.
	 * @param machoHeaderOffsets A list of provider offsets where PRELINK Mach-O headers start (not 
	 *   including the "System" Mach-O at offset 0).
	 * @param monitor A monitor
	 * @return A bidirectional mapping of PRELINK XML to Mach-O header offset in the given provider.
	 * @throws MachException If there was a problem parsing a Mach-O header.
	 * @throws IOException If there was an IO-related issue mapping PRELINK XML to Mach-O headers.
	 */
	public static BidiMap<PrelinkMap, Long> matchPrelinkToMachoHeaderOffsets(ByteProvider provider,
			List<PrelinkMap> prelinkList, List<Long> machoHeaderOffsets, TaskMonitor monitor)
			throws MachException, IOException {

		monitor.setMessage("Matching PRELINK to Mach-O headers...");
		monitor.initialize(prelinkList.size());

		BidiMap<PrelinkMap, Long> map = new DualHashBidiMap<>();

		// For pre-iOS 12, we can use the PrelinkExecutableLoadAddr field to match PrelinkMap
		// entries to Mach-O offsets.  For iOS 12, PrelinkExecutableLoadAddr is gone so we use
		// the new ModuleIndex field instead. 
		long maxModuleIndex =
			prelinkList.stream().mapToLong(info -> info.getPrelinkModuleIndex()).max().orElse(-1);
		if (maxModuleIndex >= 0) {
			Msg.debug(MachoPrelinkUtils.class, String.format(
				"Using ModuleIndex to find Mach-O offsets (%d module indexes, %d indexed modules found)",
				maxModuleIndex + 1, machoHeaderOffsets.size()));
			if (maxModuleIndex + 1 != machoHeaderOffsets.size()) {
				Msg.warn(MachoPrelinkUtils.class,
					String.format(
						"Maximum ModuleIndex is not consistent with # of modules found! (%d vs %d)",
						maxModuleIndex + 1, machoHeaderOffsets.size()));
			}

			for (PrelinkMap info : prelinkList) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.incrementProgress(1);

				int machoOffsetIndex = (int) info.getPrelinkModuleIndex();
				if (machoOffsetIndex != -1 && machoOffsetIndex < machoHeaderOffsets.size()) {
					long machoHeaderOffset = machoHeaderOffsets.get(machoOffsetIndex);
					map.put(info, machoHeaderOffset);
				}
			}

		}
		else {
			Msg.debug(MachoPrelinkUtils.class,
				String.format(
					"Using PrelinkExecutableLoadAddr to find Mach-O offsets (%d modules found)",
					machoHeaderOffsets.size()));

			MachHeader machoHeader =
				MachHeader.createMachHeader(RethrowContinuesFactory.INSTANCE, provider, 0, true);
			machoHeader.parse();
			long prelinkStart = MachoPrelinkUtils.getPrelinkStartAddr(machoHeader);
			for (PrelinkMap info : prelinkList) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.incrementProgress(1);

				map.put(info,
					info.getPrelinkExecutableLoadAddr() - prelinkStart + machoHeaderOffsets.get(0));

			}
		}

		return map;
	}

	/**
	 * Gets the start address of the PRELINK Mach-O's in memory.
	 * <p>
	 * NOTE: This method only works for pre iOS 12 binaries.  If called on an iOS 12 binary, it will
	 * fail and return 0 because the __PRELINK_TEXT segment has a size of 0.  In this case, some
	 * other means of computing the start address of the PRELINK Mach-O's must be used.
	 * 
	 * @param header The Mach-O header.
	 * @return The start address of the PRELINK Mach-O's in memory, or 0 if it could not be found.
	 */
	public static long getPrelinkStartAddr(MachHeader header) {
		SegmentCommand prelinkTextSegment = header.getSegment(SegmentNames.SEG_PRELINK_TEXT);
		if (prelinkTextSegment != null && prelinkTextSegment.getVMsize() > 0) {
			return prelinkTextSegment.getVMaddress();
		}

		return 0;
	}

	/**
	 * Checks to see if the provider at the given offset represents a valid Mach-O file that we can
	 * load (ie, we support the processor).  If it does, a valid {@link LoadSpec} for the Mach-O is 
	 * returned.
	 * 
	 * @param provider The provider.
	 * @param offset The offset within the provider to check.
	 * @return True A valid {@link LoadSpec} for the Mach-O at the given provider's offset, or null 
	 *   if it is not a Mach-O or a valid {@link LoadSpec} could not be found.
	 * @throws IOException if there was an IO-related problem.
	 */
	private static LoadSpec getMachoLoadSpec(ByteProvider provider, long offset)
			throws IOException {
		Collection<LoadSpec> loadSpecs = new MachoLoader().findSupportedLoadSpecs(
			new ByteProviderWrapper(provider, offset, provider.length() - offset));

		// Getting a LoadSpec back means it's a Mach-O we can load.  We also need to make sure
		// the LoadSpec has a language/compiler spec defined to know we support the processor the
		// loader detected.
		if (!loadSpecs.isEmpty()) {
			LoadSpec loadSpec = loadSpecs.iterator().next();
			if (loadSpec.getLanguageCompilerSpec() != null) {
				return loadSpec;
			}
		}
		return null;
	}
}
