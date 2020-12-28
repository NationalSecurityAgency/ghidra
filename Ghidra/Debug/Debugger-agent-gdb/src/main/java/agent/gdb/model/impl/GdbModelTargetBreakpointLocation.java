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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.gdb.manager.breakpoint.GdbBreakpointLocation;
import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import generic.Unique;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.attributes.TargetObjectRefList;
import ghidra.dbg.attributes.TargetObjectRefList.DefaultTargetObjectRefList;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;

@TargetObjectSchemaInfo(name = "BreakpointLocation", elements = {
	@TargetElementType(type = Void.class)
}, attributes = {
	@TargetAttributeType(type = Void.class)
})
public class GdbModelTargetBreakpointLocation
		extends DefaultTargetObject<TargetObject, GdbModelTargetBreakpointSpec>
		implements TargetBreakpointLocation<GdbModelTargetBreakpointLocation> {
	protected static String indexLocation(GdbBreakpointLocation loc) {
		return PathUtils.makeIndex(loc.getSub());
	}

	protected static String keyLocation(GdbBreakpointLocation loc) {
		return PathUtils.makeKey(indexLocation(loc));
	}

	protected final GdbModelImpl impl;
	protected final GdbBreakpointLocation loc;

	protected Address address;
	protected Integer length;
	protected final TargetObjectRefList<GdbModelTargetInferior> affects;
	protected String display;

	public GdbModelTargetBreakpointLocation(GdbModelTargetBreakpointSpec spec,
			GdbBreakpointLocation loc) {
		super(spec.impl, spec, keyLocation(loc), "BreakpointLocation");
		this.impl = spec.impl;
		this.loc = loc;

		this.affects = doGetAffects();
		if (!spec.info.getType().isWatchpoint()) {
			this.address = doGetAddress();
			this.length = 1;
			doChangeAttributes("Initialized");
		}
		assert !this.affects.isEmpty();
	}

	protected void doChangeAttributes(String reason) {
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			AFFECTS_ATTRIBUTE_NAME, affects,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, length,
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay(),
			UPDATE_MODE_ATTRIBUTE_NAME, TargetUpdateMode.FIXED //
		), reason);
	}

	/**
	 * Initialize watchpoint attributes via expression evaluation
	 * 
	 * <p>
	 * This has to be async because it involves interacting with GDB. GDB does not give the address
	 * or location information for location-specified watchpoints. Instead we take the expression
	 * and ask GDB to evaluate its address and size.
	 * 
	 * @return a future which completes when the (watchpoint) location has been initialized.
	 */
	protected CompletableFuture<Void> initWpt() {
		assert loc.getAddr() == null;
		String what = parent.info.getWhat();
		if (!what.startsWith(GdbBreakpointLocation.WATCHPOINT_LOCATION_PREFIX)) {
			throw new AssertionError("non-location location");
		}
		String exp = what.substring(GdbBreakpointLocation.WATCHPOINT_LOCATION_PREFIX.length());
		GdbModelTargetInferior inf = Unique.assertOne(affects);
		String addrSizeExp = String.format("{(long long)&(%s), (long long)sizeof(%s)}", exp, exp);
		return inf.inferior.evaluate(addrSizeExp).thenAccept(result -> {
			List<Long> vals;
			try {
				vals = GdbCValueParser.parseArray(result).expectLongs();
			}
			catch (GdbParseError e) {
				throw new AssertionError("Unexpected result type: " + result, e);
			}
			if (vals.size() != 2) {
				throw new AssertionError("Unexpected result count: " + result);
			}

			address = impl.space.getAddress(vals.get(0));
			length = vals.get(1).intValue();
			doChangeAttributes("Initialized");
		});
	}

	protected String computeDisplay() {
		return String.format("%d.%d %s", parent.info.getNumber(), loc.getSub(), address);
	}

	protected Address doGetAddress() {
		return impl.space.getAddress(loc.addrAsLong());
	}

	@Override
	public Integer getLength() {
		return length;
	}

	protected TargetObjectRefList<GdbModelTargetInferior> doGetAffects() {
		return loc.getInferiorIds()
				.stream()
				.map(impl.session.inferiors::getTargetInferior)
				.collect(Collectors.toCollection(DefaultTargetObjectRefList::new));
	}

	@Override
	public TargetObjectRefList<GdbModelTargetInferior> getAffects() {
		return affects;
	}

	@Override
	public GdbModelTargetBreakpointSpec getSpecification() {
		return parent;
	}
}
