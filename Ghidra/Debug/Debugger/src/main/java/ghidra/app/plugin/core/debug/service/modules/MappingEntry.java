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

import java.net.URL;
import java.util.Objects;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin.ChangeCollector;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.util.Msg;

class MappingEntry {
	final TraceStaticMapping mapping;
	final TraceAddressSnapRange tasr;

	Program program;
	private AddressRange staticRange;

	public MappingEntry(TraceStaticMapping mapping) {
		this.mapping = mapping;
		// Yes, mapping range and lifespan are immutable
		this.tasr = new ImmutableTraceAddressSnapRange(mapping.getTraceAddressRange(),
			mapping.getLifespan());
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof MappingEntry that)) {
			return false;
		}
		// Yes, use identity, since it should be the same trace db records
		if (this.mapping != that.mapping) {
			return false;
		}
		if (this.program != that.program) {
			return false;
		}
		if (!Objects.equals(this.staticRange, that.staticRange)) {
			return false;
		}
		return true;
	}

	public Trace getTrace() {
		return mapping.getTrace();
	}

	Address addrOrMin(Program program, String addr) {
		AddressFactory factory = program.getAddressFactory();
		Address result = factory.getAddress(addr);
		if (result == null) {
			Msg.warn(this, "Mapping entry has invalid static address: " + addr);
			result = factory.getDefaultAddressSpace().getMinAddress();
		}
		return result;
	}

	Address addrOrMax(Address start, long length) {
		Address result = start.addWrapSpace(length);
		if (result.compareTo(start) < 0) {
			Msg.warn(this, "Mapping entry caused overflow in static address space");
			return start.getAddressSpace().getMaxAddress();
		}
		return result;
	}

	void clearProgram(ChangeCollector cc, Program program) {
		this.program = null;
		this.staticRange = null;
		cc.traceAffected(getTrace());
		cc.programAffected(program);
	}

	void fillProgram(ChangeCollector cc, Program program) {
		this.program = program;
		Address minAddr = addrOrMin(program, mapping.getStaticAddress());
		Address maxAddr = addrOrMax(minAddr, mapping.getLength() - 1);
		this.staticRange = new AddressRangeImpl(minAddr, maxAddr);
		cc.traceAffected(getTrace());
		cc.programAffected(program);
	}

	public AddressRange getTraceRange() {
		return mapping.getTraceAddressRange();
	}

	public Address getTraceAddress() {
		return mapping.getMinTraceAddress();
	}

	public AddressRange getStaticRange() {
		return staticRange;
	}

	public Address getStaticAddress() {
		if (staticRange == null) {
			return null;
		}
		return staticRange.getMinAddress();
	}

	public TraceSpan getTraceSpan() {
		return new DefaultTraceSpan(mapping.getTrace(), mapping.getLifespan());
	}

	public TraceAddressSnapRange getTraceAddressSnapRange() {
		return tasr;
	}

	public boolean isInTraceRange(Address address, Long snap) {
		return mapping.getTraceAddressRange().contains(address) &&
			(snap == null || mapping.getLifespan().contains(snap));
	}

	public boolean isInTraceRange(AddressRange rng, Long snap) {
		return mapping.getTraceAddressRange().intersects(rng) &&
			(snap == null || mapping.getLifespan().contains(snap));
	}

	public boolean isInTraceLifespan(long snap) {
		return mapping.getLifespan().contains(snap);
	}

	public boolean isInProgramRange(Address address) {
		if (staticRange == null) {
			return false;
		}
		return staticRange.contains(address);
	}

	public boolean isInProgramRange(AddressRange rng) {
		if (staticRange == null) {
			return false;
		}
		return staticRange.intersects(rng);
	}

	protected Address mapTraceAddressToProgram(Address address) {
		assert isInTraceRange(address, null);
		long offset = address.subtract(mapping.getMinTraceAddress());
		return staticRange.getMinAddress().addWrapSpace(offset);
	}

	public ProgramLocation mapTraceAddressToProgramLocation(Address address) {
		if (program == null) {
			throw new IllegalStateException("Static program is not opened");
		}
		return new ProgramLocation(program, mapTraceAddressToProgram(address));
	}

	public AddressRange mapTraceRangeToProgram(AddressRange rng) {
		assert isInTraceRange(rng, null);
		AddressRange part = rng.intersect(mapping.getTraceAddressRange());
		Address min = mapTraceAddressToProgram(part.getMinAddress());
		Address max = mapTraceAddressToProgram(part.getMaxAddress());
		return new AddressRangeImpl(min, max);
	}

	protected Address mapProgramAddressToTrace(Address address) {
		assert isInProgramRange(address);
		long offset = address.subtract(staticRange.getMinAddress());
		return mapping.getMinTraceAddress().addWrapSpace(offset);
	}

	protected TraceLocation mapProgramAddressToTraceLocation(Address address) {
		return new DefaultTraceLocation(mapping.getTrace(), null, mapping.getLifespan(),
			mapProgramAddressToTrace(address));
	}

	public AddressRange mapProgramRangeToTrace(AddressRange rng) {
		assert (rng.intersects(staticRange));
		AddressRange part = rng.intersect(staticRange);
		Address min = mapProgramAddressToTrace(part.getMinAddress());
		Address max = mapProgramAddressToTrace(part.getMaxAddress());
		return new AddressRangeImpl(min, max);
	}

	public boolean isStaticProgramOpen() {
		return program != null;
	}

	public URL getStaticProgramUrl() {
		return mapping.getStaticProgramURL();
	}
}
