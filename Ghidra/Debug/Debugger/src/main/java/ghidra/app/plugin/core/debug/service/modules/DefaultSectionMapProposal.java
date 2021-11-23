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

import java.util.Map;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.SectionMapProposal;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;

public class DefaultSectionMapProposal
		extends AbstractMapProposal<TraceSection, MemoryBlock, SectionMapEntry>
		implements SectionMapProposal {

	/**
	 * A section-block entry in a proposed section map
	 */
	public static class DefaultSectionMapEntry extends AbstractMapEntry<TraceSection, MemoryBlock>
			implements SectionMapEntry {

		/**
		 * Construct a section map entry
		 * 
		 * <p>
		 * Generally, only the service implementation should construct an entry. See
		 * {@link DebuggerStaticMappingService#proposeSectionMap(TraceSection, Program, MemoryBlock)}
		 * and related to obtain these.
		 * 
		 * @param section the section
		 * @param program the program containing the matched block
		 * @param block the matched memory block
		 */
		protected DefaultSectionMapEntry(TraceSection section, Program program, MemoryBlock block) {
			super(section.getTrace(), section, program, block);
		}

		@Override
		public TraceModule getModule() {
			return getFromObject().getModule();
		}

		@Override
		public TraceSection getSection() {
			return getFromObject();
		}

		@Override
		public Range<Long> getFromLifespan() {
			return getModule().getLifespan();
		}

		@Override
		public AddressRange getFromRange() {
			return getSection().getRange();
		}

		@Override
		public MemoryBlock getBlock() {
			return getToObject();
		}

		@Override
		public AddressRange getToRange() {
			return new AddressRangeImpl(getBlock().getStart(), getBlock().getEnd());
		}

		@Override
		public void setBlock(Program program, MemoryBlock block) {
			setToObject(program, block);
		}
	}

	protected static class SectionMatcher extends Matcher<TraceSection, MemoryBlock> {
		public SectionMatcher(TraceSection section, MemoryBlock block) {
			super(section, block);
		}

		@Override
		protected AddressRange getFromRange() {
			return fromObject == null ? null : fromObject.getRange();
		}

		@Override
		protected AddressRange getToRange() {
			return toObject == null ? null
					: new AddressRangeImpl(toObject.getStart(), toObject.getEnd());
		}
	}

	protected static class SectionMatcherMap
			extends MatcherMap<String, TraceSection, MemoryBlock, SectionMatcher> {
		@Override
		protected SectionMatcher newMatcher(TraceSection section, MemoryBlock block) {
			return new SectionMatcher(section, block);
		}

		@Override
		protected String getFromJoinKey(TraceSection section) {
			return section.getName();
		}

		@Override
		protected String getToJoinKey(MemoryBlock block) {
			return block.getName();
		}
	}

	protected final TraceModule module;
	protected final SectionMatcherMap matchers = new SectionMatcherMap();

	protected DefaultSectionMapProposal(TraceModule module, Program program) {
		super(module.getTrace(), program);
		this.module = module;
		processModule();
		processProgram();
	}

	protected DefaultSectionMapProposal(TraceSection section, Program program, MemoryBlock block) {
		super(section.getTrace(), program);
		this.module = section.getModule();
		matchers.processFromObject(section);
		matchers.processToObject(block);
	}

	@Override
	public TraceModule getModule() {
		return module;
	}

	private void processModule() {
		for (TraceSection section : module.getSections()) {
			matchers.processFromObject(section);
		}
	}

	private void processProgram() {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			matchers.processToObject(block);
		}
	}

	@Override
	public double computeScore() {
		return matchers.averageScore();
	}

	@Override
	public Map<TraceSection, SectionMapEntry> computeMap() {
		return matchers
				.computeMap(m -> new DefaultSectionMapEntry(m.fromObject, program, m.toObject));
	}

	@Override
	public MemoryBlock getToObject(TraceSection from) {
		return matchers.getToObject(from);
	}
}
