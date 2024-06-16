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
package ghidra.app.plugin.core.debug.disassemble;

import java.util.*;
import java.util.Map.Entry;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import generic.jar.ResourceFile;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingActionContext;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.UnionAddressSetView;

@PluginInfo(
	shortDescription = "Disassemble trace bytes in the debugger",
	description = "Provides 'Disassemble as' actions for traces.",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
	},
	eventsProduced = {
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerPlatformService.class,
	},
	servicesProvided = {
	})
public class DebuggerDisassemblerPlugin extends Plugin implements PopupActionProvider {

	public static RegisterValue deriveAlternativeDefaultContext(Language language,
			LanguageID alternative, Address address) {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		Language altLang;
		try {
			altLang = langServ.getLanguage(alternative);
		}
		catch (LanguageNotFoundException e) {
			// I just looked it up
			throw new AssertionError(e);
		}

		ProgramContextImpl ctx = new ProgramContextImpl(altLang);
		altLang.applyContextSettings(ctx);
		Address altAddress = altLang.getAddressFactory()
				.getAddressSpace(address.getAddressSpace().getPhysicalSpace().getName())
				.getAddress(address.getOffset());

		RegisterValue altVal = ctx.getDisassemblyContext(altAddress).getBaseRegisterValue();
		RegisterValue result =
			new RegisterValue(language.getContextBaseRegister(), altVal.toBytes());
		return result;
	}

	/**
	 * Determine whether the given address is known, or has ever been known in read-only memory, for
	 * the given snapshot
	 * 
	 * <p>
	 * This first examines the memory state. If the current state is {@link TraceMemoryState#KNOWN},
	 * then it returns the snap for the entry. (Because scratch snaps are allowed, the returned snap
	 * may be from an "earlier" snap in the viewport.) Then, it examines the most recent entry. If
	 * one cannot be found, or the found entry's state is <em>not</em>
	 * {@link TraceMemoryState#KNOWN}, it returns null. If the most recent (but not current) entry
	 * is {@link TraceMemoryState#KNOWN}, then it checks whether or not the memory is writable. If
	 * it's read-only, then the snap for that most-recent entry is returned. Otherwise, this check
	 * assumes the memory could have changed since, and so it returns null.
	 * 
	 * @param start the address to check
	 * @param trace the trace whose memory to examine
	 * @param snap the lastest snapshot key, possibly a scratch snapshot, to consider
	 * @return null to indicate the address failed the test, or the defining snapshot key if the
	 *         address passed the test.
	 */
	public static Long isKnownRWOrEverKnownRO(Address start, Trace trace, long snap) {
		TraceMemoryManager memoryManager = trace.getMemoryManager();
		Entry<Long, TraceMemoryState> kent = memoryManager.getViewState(snap, start);
		if (kent != null && kent.getValue() == TraceMemoryState.KNOWN) {
			return kent.getKey();
		}
		Entry<TraceAddressSnapRange, TraceMemoryState> mrent =
			memoryManager.getViewMostRecentStateEntry(snap, start);
		if (mrent == null || mrent.getValue() != TraceMemoryState.KNOWN) {
			// It has never been known up to this snap
			return null;
		}
		TraceMemoryRegion region =
			memoryManager.getRegionContaining(mrent.getKey().getY1(), start);
		if (region == null || region.isWrite()) {
			// It could have changed this snap, so unknown
			return null;
		}
		return mrent.getKey().getY1();
	}

	/**
	 * Compute a lazy address set for restricting auto-disassembly
	 * 
	 * <p>
	 * The view contains the addresses in {@code known | (readOnly & everKnown)}, where {@code
	 * known} is the set of addresses in the {@link TraceMemoryState#KNOWN} state, {@code readOnly}
	 * is the set of addresses in a {@link TraceMemoryRegion} having
	 * {@link TraceMemoryRegion#isWrite()} false, and {@code everKnown} is the set of addresses in
	 * the {@link TraceMemoryState#KNOWN} state in any previous snapshot.
	 * 
	 * <p>
	 * In plainer English, we want addresses that have freshly read bytes right now, or addresses in
	 * read-only memory that have ever been read. Anything else is either the default 0s (never
	 * read), or could have changed since last read, and so we will refrain from disassembling.
	 * 
	 * <p>
	 * TODO: Is this composition of laziness upon laziness efficient enough? Can experiment with
	 * ordering of address-set-view "expression" to optimize early termination.
	 * 
	 * @param start the intended starting address for disassembly
	 * @param trace the trace whose memory to disassemble
	 * @param snap the current snapshot key, possibly a scratch snapshot
	 * @return the lazy address set
	 */
	public static AddressSetView computeAutoDisassembleAddresses(Address start, Trace trace,
			long snap) {
		Long ks = isKnownRWOrEverKnownRO(start, trace, snap);
		if (ks == null) {
			return null;
		}
		TraceMemoryManager memoryManager = trace.getMemoryManager();
		AddressSetView readOnly =
			memoryManager.getRegionsAddressSetWith(ks, r -> !r.isWrite());
		AddressSetView everKnown = memoryManager.getAddressesWithState(Lifespan.since(ks),
			s -> s == TraceMemoryState.KNOWN);
		AddressSetView roEverKnown = new IntersectionAddressSetView(readOnly, everKnown);
		AddressSetView known =
			memoryManager.getAddressesWithState(ks, s -> s == TraceMemoryState.KNOWN);
		AddressSetView disassemblable = new UnionAddressSetView(known, roEverKnown);
		return disassemblable;
	}

	CurrentPlatformTraceDisassembleAction actionDisassemble;
	CurrentPlatformTracePatchInstructionAction actionPatchInstruction;

	public DebuggerDisassemblerPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		tool.addPopupActionProvider(this);
		createActions();
	}

	protected void createActions() {
		actionDisassemble = new CurrentPlatformTraceDisassembleAction(this);
		actionPatchInstruction = new CurrentPlatformTracePatchInstructionAction(this);

		tool.addAction(actionDisassemble);
		tool.addAction(actionPatchInstruction);
	}

	/**
	 * Get languages which have the same parser, but alternative initial contexts
	 * 
	 * @param language the language for which alternatives are desired
	 * @return the collections of languages
	 */
	protected Collection<LanguageID> getAlternativeLanguageIDs(Language language) {
		// One of the alternatives is the language's actual default
		LanguageDescription desc = language.getLanguageDescription();
		if (!(desc instanceof SleighLanguageDescription)) {
			return List.of();
		}
		SleighLanguageDescription sld = (SleighLanguageDescription) desc;
		ResourceFile slaFile = sld.getSlaFile();

		List<LanguageID> result = new ArrayList<>();
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		for (LanguageDescription altDesc : langServ.getLanguageDescriptions(false)) {
			if (!(altDesc instanceof SleighLanguageDescription)) {
				continue;
			}
			SleighLanguageDescription altSld = (SleighLanguageDescription) altDesc;
			if (!altSld.getSlaFile().equals(slaFile)) {
				continue;
			}
			if (altSld.getEndian() != sld.getEndian()) {
				// Memory endian, not necessarily instruction endian
				continue;
			}
			result.add(altSld.getLanguageID());
		}
		return result;
	}

	protected void getActionsForLanguage(List<DockingActionIf> result,
			TracePlatform platform) {
		for (LanguageID langID : getAlternativeLanguageIDs(platform.getLanguage())) {
			result.add(new FixedPlatformTraceDisassembleAction(this, langID, platform));
			result.add(new FixedPlatformTracePatchInstructionAction(this, langID, platform));
		}
	}

	protected void getActionsForHost(List<DockingActionIf> result, Trace trace) {
		Language language = trace.getBaseLanguage();
		if (language.getProcessor() == Processor.toProcessor("DATA")) {
			return;
		}
		getActionsForLanguage(result, trace.getPlatformManager().getHostPlatform());
	}

	protected void getActionsForGuest(List<DockingActionIf> result,
			TraceGuestPlatform guest, Address hostAddress) {
		if (!guest.getHostAddressSet().contains(hostAddress)) {
			return;
		}
		/*
		 * TODO: May need to distinguish platform if many for same language, esp., if mapped
		 * differently
		 */
		getActionsForLanguage(result, guest);
	}

	protected void getActionsForAllGuests(List<DockingActionIf> result, Trace trace,
			Address address) {
		for (TraceGuestPlatform guest : trace.getPlatformManager().getGuestPlatforms()) {
			getActionsForGuest(result, guest, address);
		}
	}

	protected List<DockingActionIf> getActionsFor(List<DockingActionIf> result, Trace trace,
			long snap, Address address) {
		getActionsForHost(result, trace);
		getActionsForAllGuests(result, trace, address);
		return result;
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		/**
		 * I could use Navigatable.isDynamic, but it seems more appropriate, since the types are in
		 * scope here, to check for an actual trace.
		 */
		if (!(context instanceof DebuggerListingActionContext lac)) {
			return null;
		}
		Address address = lac.getAddress();
		if (address == null) {
			return null;
		}
		TraceProgramView view = lac.getProgram();
		return getActionsFor(new ArrayList<>(), view.getTrace(), view.getSnap(), address);
	}
}
