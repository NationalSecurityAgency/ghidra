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

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils.Extrema;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.modules.ModuleMapProposal;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.MathUtilities;

public class DefaultModuleMapProposal
		extends AbstractMapProposal<TraceModule, Program, ModuleMapEntry>
		implements ModuleMapProposal {
	protected static final int BLOCK_BITS = 12;
	protected static final int BLOCK_SIZE = 1 << BLOCK_BITS;
	protected static final long BLOCK_MASK = -1L << BLOCK_BITS;

	protected static AddressRange quantize(AddressRange range) {
		AddressSpace space = range.getAddressSpace();
		Address min = space.getAddress(range.getMinAddress().getOffset() & BLOCK_MASK);
		Address max = space.getAddress(range.getMaxAddress().getOffset() | ~BLOCK_MASK);
		return new AddressRangeImpl(min, max);
	}

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
			if (block.isArtificial()) {
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
		public static AddressRange computeImageRange(Program program) {
			Extrema extrema = new Extrema();
			// TODO: How to handle Harvard architectures?
			for (MemoryBlock block : program.getMemory().getBlocks()) {
				if (!includeBlock(program, block)) {
					continue;
				}
				// includeBlock checks address space is same as image base
				extrema.consider(block.getAddressRange());
			}
			if (program.getImageBase().getOffset() != 0) {
				extrema.consider(program.getImageBase());
			}
			return extrema.getRange();
		}

		protected AddressRange moduleRange;
		protected AddressRange imageRange;
		protected boolean memorize = false;

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
			this.imageRange = quantize(computeImageRange(program));
		}

		@Override
		public TraceModule getModule() {
			return getFromObject();
		}

		@Override
		public Lifespan getFromLifespan() {
			return getModule().getLifespan();
		}

		private long getLength() {
			return MathUtilities.unsignedMin(moduleRange.getLength(), imageRange.getLength());
		}

		@Override
		public AddressRange getFromRange() {
			try {
				return new AddressRangeImpl(moduleRange.getMinAddress(), getLength());
			}
			catch (AddressOverflowException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public AddressRange getModuleRange() {
			return moduleRange;
		}

		@Override
		public void setProgram(Program program) {
			setToObject(program, program);
			this.imageRange = quantize(computeImageRange(program));
		}

		@Override
		public AddressRange getToRange() {
			try {
				return new AddressRangeImpl(imageRange.getMinAddress(), getLength());
			}
			catch (AddressOverflowException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public boolean isMemorize() {
			return memorize;
		}

		@Override
		public void setMemorize(boolean memorize) {
			this.memorize = memorize;
		}
	}

	protected final TraceModule module;

	// indexed by region's offset from module base
	protected final NavigableMap<Long, ModuleRegionMatcher> matchers = new TreeMap<>();
	protected AddressRange imageRange;
	protected AddressRange moduleRange;

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
		imageRange = quantize(DefaultModuleMapEntry.computeImageRange(program));
		Address imageBase = imageRange.getMinAddress(); // not precisely, but good enough
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
		moduleRange = quantize(module.getRange());
		Address moduleBase = moduleRange.getMinAddress();
		Lifespan lifespan = module.getLifespan();
		for (TraceMemoryRegion region : module.getTrace()
				.getMemoryManager()
				.getRegionsIntersecting(lifespan, moduleRange)) {
			Address min = region instanceof TraceObjectMemoryRegion objReg
					? objReg.getMinAddress(lifespan.lmin())
					: region.getMinAddress();
			getMatcher(min.subtract(moduleBase)).region = region;
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
