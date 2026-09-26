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
package ghidra.app.decompiler.inline;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompileCallback;
import ghidra.app.decompiler.spi.PcodeOverrideHook;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PatchEncoder;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.NoValueException;

/**
 * Base {@link PcodeOverrideHook} that dispatches IFC-style synthetic
 * pcode from per-caller user PropertyMaps an analyzer publishes.
 * Each cached function may have any combination of:
 *
 * <ul>
 * <li>{@code MultiBranchback:<entry>} - {@link StringPropertyMap} of
 *     comma-separated hex offsets; produces a linear-CBRANCH switch on
 *     the dialect's ifc_lp register.
 * <li>{@code Branchback:<entry>} - {@link LongPropertyMap}; produces a
 *     BRANCH (or CALL + conditional BRANCH for the tail-call case).
 * <li>{@code InlineCall:<entry>} - {@link LongPropertyMap}; produces
 *     {@code CALL X; BRANCH inst_next} at an ifcall whose body is a
 *     single tail-call.
 * <li>{@code InlineBody:<entry>} - {@link LongPropertyMap}; inlines
 *     the body's prototype pcode in place of the ifcall.
 * </ul>
 *
 * <p>For ifcall instances with no PropertyMap entry the hook falls back
 * to the standard {@code ifc_lp = inst_next; IFC_ON = 1; BRANCH T}
 * synth.  For ifret instances with no PropertyMap entry the hook emits
 * empty pcode, suppressing the prototype's unresolvable
 * {@code BRANCHIND[ifc_lp]} so the decompiler proceeds via natural
 * fall-through (matching the runtime nop case when {@code ifc_on=0}).
 *
 * <p>Concrete subclasses just declare their {@link IfcDialect} and a
 * processor predicate.
 */
public abstract class IfcPropertyMapPcodeOverrideHook implements PcodeOverrideHook {

	protected abstract IfcDialect getDialect();

	/**
	 * True if {@code program}'s processor is the one this hook targets.
	 * Combined with the dialect's IFC_ON-register presence in
	 * {@link #canHandle(Program)} so that programs that haven't loaded
	 * the IFC language extensions aren't slowed down.
	 */
	protected abstract boolean isApplicableProcessor(Program program);

	@Override
	public boolean canHandle(Program program) {
		if (!isApplicableProcessor(program)) {
			return false;
		}
		return program.getLanguage().getRegister(getDialect().getIfcOnRegisterName()) != null;
	}

	@Override
	public boolean emit(Program program, Function cachedFunction, Address addr,
			Instruction instr, PatchEncoder out) throws IOException, NoValueException {
		IfcPcodeEmitter emitter = new IfcPcodeEmitter(program, getDialect());
		PropertyMapManager pmm = program.getUsrPropertyManager();
		String fnHex = Long.toHexString(cachedFunction.getEntryPoint().getOffset());
		AddressSpace space = addr.getAddressSpace();

		StringPropertyMap multi = pmm.getStringPropertyMap("MultiBranchback:" + fnHex);
		if (multi != null && multi.hasProperty(addr)) {
			List<Address> targets = parseHexAddrList(multi.getString(addr), space);
			if (!targets.isEmpty()) {
				emitter.emitMultiBranchback(out, addr, instr, targets);
				return true;
			}
		}

		LongPropertyMap branchback = pmm.getLongPropertyMap("Branchback:" + fnHex);
		if (branchback != null && branchback.hasProperty(addr)) {
			Address target = space.getAddress(branchback.getLong(addr));
			emitter.emitSingleBranchback(out, cachedFunction, addr, instr, target);
			return true;
		}

		String mn = instr.getMnemonicString().toLowerCase();
		IfcDialect d = getDialect();

		if (d.getIfretMnemonics().contains(mn)) {
			// Suppress the natural BRANCHIND[ifc_lp] (which the decompiler
			// would treat as an unresolvable jumptable).  Empty pcode +
			// natural fall-through matches the runtime nop case.
			DecompileCallback.encodeInstruction(out, addr, new PcodeOp[0], instr.getLength(),
				0, program.getAddressFactory());
			return true;
		}

		if (d.getIfcallMnemonics().contains(mn)) {
			LongPropertyMap inlineCall = pmm.getLongPropertyMap("InlineCall:" + fnHex);
			if (inlineCall != null && inlineCall.hasProperty(addr)) {
				Address xTarget = space.getAddress(inlineCall.getLong(addr));
				emitter.emitInlineCall(out, addr, instr, xTarget);
				return true;
			}
			LongPropertyMap inlineBody = pmm.getLongPropertyMap("InlineBody:" + fnHex);
			if (inlineBody != null && inlineBody.hasProperty(addr)) {
				Address bodyStart = space.getAddress(inlineBody.getLong(addr));
				if (emitter.emitInlineBody(out, addr, instr, bodyStart)) {
					return true;
				}
			}
			return emitter.emitIfcallSynth(out, addr, instr);
		}
		return false;
	}

	private static List<Address> parseHexAddrList(String csv, AddressSpace space) {
		if (csv == null || csv.isEmpty()) {
			return List.of();
		}
		String[] hexes = csv.split(",");
		List<Address> targets = new ArrayList<>(hexes.length);
		for (String h : hexes) {
			try {
				targets.add(space.getAddress(Long.parseLong(h.trim(), 16)));
			}
			catch (NumberFormatException e) {
				// skip malformed entries
			}
		}
		return targets;
	}
}
