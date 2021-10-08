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

import agent.gdb.manager.breakpoint.GdbBreakpointLocation;
import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import generic.Unique;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

@TargetObjectSchemaInfo(
	name = "BreakpointLocation",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) })
public class GdbModelTargetBreakpointLocation
		extends DefaultTargetObject<TargetObject, GdbModelTargetBreakpointSpec>
		implements TargetBreakpointLocation {

	/** prefix used in GDB's watchpoint specs for static locations */
	protected static final String LOC_PREFIX = "-location";

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
	protected String display;

	public GdbModelTargetBreakpointLocation(GdbModelTargetBreakpointSpec spec,
			GdbBreakpointLocation loc) {
		super(spec.impl, spec, keyLocation(loc), "BreakpointLocation");
		this.impl = spec.impl;
		this.loc = loc;
		impl.addModelObject(loc, this);

		if (!spec.info.getType().isWatchpoint()) {
			this.address = doGetAddress();
			this.length = 1;
			doChangeAttributes("Initialized");
		}
	}

	protected void doChangeAttributes(String reason) {
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			ADDRESS_ATTRIBUTE_NAME, address,
			LENGTH_ATTRIBUTE_NAME, length,
			DISPLAY_ATTRIBUTE_NAME, display = computeDisplay()),
			reason);
		placeLocations();
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
		String exp = what.startsWith(LOC_PREFIX) ? what.substring(LOC_PREFIX.length()) : what;
		int iid = Unique.assertOne(loc.getInferiorIds());
		GdbModelTargetInferior inf = impl.session.inferiors.getTargetInferior(iid);
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
		}).exceptionally(ex -> {
			Msg.warn(this, "Could not evaluated breakpoint location and/or size: " + ex);
			address = impl.space.getAddress(0);
			length = 1;
			doChangeAttributes("Defaulted for eval/parse error");
			return null;
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

	protected void placeLocations() {
		for (GdbModelTargetInferior inf : impl.session.inferiors.getCachedElements().values()) {
			if (loc.getInferiorIds().contains(inf.inferior.getId())) {
				inf.addBreakpointLocation(this);
			}
			else {
				inf.removeBreakpointLocation(this);
			}
		}
	}

	@Override
	protected void doInvalidate(TargetObject branch, String reason) {
		removeLocations();
		super.doInvalidate(branch, reason);
	}

	protected void removeLocations() {
		// TODO: Shouldn't the framework do this for us? The location is invalidated.
		for (GdbModelTargetInferior inf : impl.session.inferiors.getCachedElements().values()) {
			inf.removeBreakpointLocation(this);
		}
	}

	@Override
	public GdbModelTargetBreakpointSpec getSpecification() {
		return parent;
	}
}
