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
import java.util.function.Function;

import agent.gdb.manager.breakpoint.GdbBreakpointLocation;
import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import generic.Unique;
import ghidra.async.AsyncUtils;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
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

	protected AddressRange range;
	protected String display;

	public GdbModelTargetBreakpointLocation(GdbModelTargetBreakpointSpec spec,
			GdbBreakpointLocation loc) {
		super(spec.impl, spec, keyLocation(loc), "BreakpointLocation");
		this.impl = spec.impl;
		this.loc = loc;
		impl.addModelObject(loc, this);

		if (!spec.info.getType().isWatchpoint()) {
			Address addr = impl.space.getAddress(loc.addrAsLong());
			this.range = new AddressRangeImpl(addr, addr);
			doChangeAttributes("Initialized");
		}
	}

	protected void doChangeAttributes(String reason) {
		this.changeAttributes(List.of(), Map.of(
			SPEC_ATTRIBUTE_NAME, parent,
			RANGE_ATTRIBUTE_NAME, range,
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
		return inf.inferior.evaluate(addrSizeExp).thenApply(result -> {
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

			range = makeRange(impl.space.getAddress(vals.get(0)), vals.get(1).intValue());
			doChangeAttributes("Initialized");
			return AsyncUtils.NIL;
		}).exceptionally(ex -> {
			CompletableFuture<String> secondTry =
				inf.inferior.evaluate(String.format("(long long)&(%s)", exp));
			return secondTry.thenAccept(result -> {
				long addr;
				try {
					addr = GdbCValueParser.parseValue(result).expectLong();
				}
				catch (GdbParseError e) {
					throw new AssertionError("Unexpected result type: " + result, e);
				}
				range = makeRange(impl.space.getAddress(addr), 1);
				doChangeAttributes("Initialized, but defaulted length=1");
			}).exceptionally(ex2 -> {
				Msg.warn(this,
					"Could not evaluated breakpoint location and/or size: " + ex2);
				Address addr = impl.space.getAddress(0);
				range = new AddressRangeImpl(addr, addr);
				doChangeAttributes("Defaulted for eval/parse error");
				return null;
			});
		}).thenCompose(Function.identity());
	}

	protected String computeDisplay() {
		return String.format("%d.%d %s", parent.info.getNumber(), loc.getSub(),
			range.getMinAddress());
	}

	// Avoid the checked exception on new AddressRangeImpl(min, length)
	protected static AddressRange makeRange(Address min, int length) {
		Address max = min.add(length - 1);
		return new AddressRangeImpl(min, max);
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
	public AddressRange getRange() {
		return range;
	}

	@Override
	public GdbModelTargetBreakpointSpec getSpecification() {
		return parent;
	}
}
