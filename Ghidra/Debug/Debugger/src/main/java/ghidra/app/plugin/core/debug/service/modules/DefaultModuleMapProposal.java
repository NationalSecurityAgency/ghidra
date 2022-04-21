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
package ghidra.app.plugin.core.debug.service.modules;

import java.util.*;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ModuleMapProposal;
import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;

public class DefaultModuleMapProposal
		extends AbstractMapProposal<TraceModule, Program, ModuleMapEntry>
		implements ModuleMapProposal {

	/**
	 * A module-program entry in a proposed module map
	 */
	public static class DefaultModuleMapEntry extends AbstractMapEntry<TraceModule, Program>
			implements ModuleMapEntry {

		/**
		 * Check if a block should be included in size computations or analyzed for proposals
		 * 
		 * @param program the program containing the block
		 * @param block the block
		 * @return true if included, false otherwise
		 */
		public static boolean includeBlock(Program program, MemoryBlock block) {
			if (program.getImageBase().getAddressSpace() != block.getStart().getAddressSpace()) {
				return false;
			}
			if (!block.isLoaded()) {
				return false;
			}
			if (block.isMapped()) {
				// TODO: Determine how to handle these.
				return false;
			}
			if (block.isExternalBlock()) {
				return false;
			}
			return true;
		}

		/**
		 * Compute the "size" of an image
		 * 
		 * <p>
		 * This is considered the maximum loaded address as mapped in memory, minus the image base.
		 * 
		 * @param program the program image whose size to compute
		 * @return the size
		 */
		public static long computeImageSize(Program program) {
			Address imageBase = program.getImageBase();
			long imageSize = 0;
			// TODO: How to handle Harvard architectures?
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!includeBlock(program, block)) {
					continue;
				}
				imageSize = Math.max(imageSize, block.getEnd().subtract(imageBase) + 1);
			}
			return imageSize;
		}

		protected AddressRange moduleRange;

		/**
		 * Construct a module map entry
		 * 
		 * <p>
		 * Generally, only the service implementation should construct an entry. See
		 * {@link DebuggerStaticMappingService#proposeModuleMap(TraceModule, Program)} and related
		 * to obtain these.
		 * 
		 * @param module the module
		 * @param program the matched program
		 * @param moduleRange a range from the module base the size of the program's image
		 */
		protected DefaultModuleMapEntry(TraceModule module, Program program,
				AddressRange moduleRange) {
			super(module.getTrace(), module, program, program);
			this.moduleRange = moduleRange;
		}

		@Override
		public TraceModule getModule() {
			return getFromObject();
		}

		@Override
		public Range<Long> getFromLifespan() {
			return getModule().getLifespan();
		}

		@Override
		public AddressRange getFromRange() {
			return moduleRange;
		}

		@Override
		public AddressRange getModuleRange() {
			return moduleRange;
		}

		@Override
		public void setProgram(Program program) {
			setToObject(program, program);
			try {
				this.moduleRange =
					new AddressRangeImpl(getModule().getBase(), computeImageSize(program));
			}
			catch (AddressOverflowException e) {
				// This is terribly unlikely
				throw new IllegalArgumentException(
					"Specified program is too large for module's memory space");
			}
		}

		@Override
		public AddressRange getToRange() {
			try {
				return new AddressRangeImpl(getToProgram().getImageBase(), moduleRange.getLength());
			}
			catch (AddressOverflowException e) {
				throw new AssertionError(e);
			}
		}
	}

	protected final TraceModule module;

	// indexed by region's offset from module base
	protected final NavigableMap<Long, ModuleRegionMatcher> matchers = new TreeMap<>();
	protected Address imageBase;
	protected Address moduleBase;
	protected long imageSize;
	protected AddressRange moduleRange; // TODO: This is now in the trace schema. Use it.

	protected DefaultModuleMapProposal(TraceModule module, Program program) {
		super(module.getTrace(), program);
		this.module = module;
		processProgram();
		processModule();
	}

	@Override
	public TraceModule getModule() {
		return module;
	}

	private ModuleRegionMatcher getMatcher(long baseOffset) {
		return matchers.computeIfAbsent(baseOffset, ModuleRegionMatcher::new);
	}

	private void processProgram() {
		imageBase = program.getImageBase();
		imageSize = DefaultModuleMapEntry.computeImageSize(program);
		// TODO: How to handle Harvard architectures?
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (!DefaultModuleMapEntry.includeBlock(program, block)) {
				continue;
			}
			getMatcher(block.getStart().subtract(imageBase)).block = block;
		}
	}

	/**
	 * Must be called after processProgram, so that image size is known
	 */
	private void processModule() {
		moduleBase = module.getBase();
		try {
			moduleRange = new AddressRangeImpl(moduleBase, imageSize);
		}
		catch (AddressOverflowException e) {
			return; // Just score it as having no matches?
		}
		for (TraceMemoryRegion region : module.getTrace()
				.getMemoryManager()
				.getRegionsIntersecting(module.getLifespan(), moduleRange)) {
			getMatcher(region.getMinAddress().subtract(moduleBase)).region = region;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote some information to consider: length and case of matched image and module names,
	 *           alignment of program memory blocks to trace memory regions, etc.
	 */
	@Override
	public double computeScore() {
		return ((double) matchers.values()
				.stream()
				.reduce(0, (s, m) -> s + m.score(), Integer::sum)) /
			matchers.size();
	}

	@Override
	public Map<TraceModule, ModuleMapEntry> computeMap() {
		return Map.of(module, new DefaultModuleMapEntry(module, program, moduleRange));
	}

	@Override
	public Program getToObject(TraceModule from) {
		if (from != module) {
			return null;
		}
		return program;
	}
}
