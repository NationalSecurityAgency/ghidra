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

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import generic.jar.ResourceFile;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;

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

	protected static class Reqs {
		final DebuggerPlatformMapper mapper;
		final TraceThread thread;
		final TraceObject object;
		final TraceProgramView view;

		public Reqs(DebuggerPlatformMapper mapper, TraceThread thread, TraceObject object,
				TraceProgramView view) {
			this.mapper = mapper;
			this.thread = thread;
			this.object = object;
			this.view = view;
		}
	}

	protected static RegisterValue deriveAlternativeDefaultContext(Language language,
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

	@AutoServiceConsumed
	DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	DebuggerPlatformService platformService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	CurrentPlatformTraceDisassembleAction actionDisassemble;
	CurrentPlatformTracePatchInstructionAction actionPatchInstruction;

	public DebuggerDisassemblerPlugin(PluginTool tool) {
		super(tool);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
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
		if (!(context instanceof ListingActionContext)) {
			return null;
		}
		/**
		 * I could use Navigatable.isDynamic, but it seems more appropriate, since the types are in
		 * scope here, to check for an actual trace.
		 */
		ListingActionContext lac = (ListingActionContext) context;
		Address address = lac.getAddress();
		if (address == null) {
			return null;
		}
		Program program = lac.getProgram();
		if (!(program instanceof TraceProgramView)) {
			return null;
		}
		TraceProgramView view = (TraceProgramView) program;
		return getActionsFor(new ArrayList<>(), view.getTrace(), view.getSnap(), address);
	}
}
