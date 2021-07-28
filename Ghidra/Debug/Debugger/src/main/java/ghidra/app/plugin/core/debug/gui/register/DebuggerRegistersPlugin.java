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
package ghidra.app.plugin.core.debug.gui.register;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Element;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.services.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.model.Trace;
import ghidra.util.Msg;

@PluginInfo(
	shortDescription = "Debugger registers manager",
	description = "GUI to view and modify register values",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerModelService.class,
		DebuggerTraceManagerService.class,
		MarkerService.class, // TODO
		DataTypeManagerService.class, // For DataType selection field
	})
public class DebuggerRegistersPlugin extends AbstractDebuggerPlugin {
	private static final String KEY_SELECTION_BY_CSPEC = "selectionByCSpec";
	private static final String KEY_FAVORITES_BY_CSPEC = "favoritesByCSpec";
	private static final String KEY_DISCONNECTED_COUNT = "disconnectedCount";
	private static final String PREFIX_DISCONNECTED_PROVIDER = "disconnectedProvider";

	protected DebuggerRegistersProvider connectedProvider;

	private final Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> selectionByCSpec =
		new HashMap<>();
	private final Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> favoritesByCSpec =
		new HashMap<>();
	private final Set<DebuggerRegistersProvider> disconnectedProviders = new HashSet<>();

	public DebuggerRegistersPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		connectedProvider = createProvider(false);
		super.init();
	}

	protected DebuggerRegistersProvider createProvider(boolean isClone) {
		return new DebuggerRegistersProvider(this, selectionByCSpec, favoritesByCSpec, isClone);
	}

	protected DebuggerRegistersProvider createNewDisconnectedProvider() {
		DebuggerRegistersProvider p = createProvider(true);
		synchronized (disconnectedProviders) {
			disconnectedProviders.add(p);
		}
		return p;
	}

	protected void providerRemoved(DebuggerRegistersProvider p) {
		synchronized (disconnectedProviders) {
			disconnectedProviders.remove(p);
		}
	}

	@Override
	protected void dispose() {
		tool.removeComponentProvider(connectedProvider);
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			connectedProvider.coordinatesActivated(ev.getActiveCoordinates());
		}
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			traceClosed(ev.getTrace());
		}
	}

	private void traceClosed(Trace trace) {
		connectedProvider.traceClosed(trace);
		synchronized (disconnectedProviders) {
			for (DebuggerRegistersProvider p : disconnectedProviders) {
				p.traceClosed(trace);
			}
		}
	}

	public static String encodeSetsByCSpec(
			Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> setsByCSpec) {
		return StringUtils.join(setsByCSpec.entrySet().stream().map(ent -> {
			LanguageCompilerSpecPair lcsp = ent.getKey();
			String regs = StringUtils.join(
				ent.getValue().stream().map(Register::getName).collect(Collectors.toList()), ',');
			return lcsp.languageID + "/" + lcsp.compilerSpecID + ":" + regs;
		}).collect(Collectors.toList()), ';');
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		// NOTE: No point in saving disconnected providers here
		String selectionByCSpecString = encodeSetsByCSpec(selectionByCSpec);
		saveState.putString(KEY_SELECTION_BY_CSPEC, selectionByCSpecString);
		String favoritesByCSpecString = encodeSetsByCSpec(favoritesByCSpec);
		saveState.putString(KEY_FAVORITES_BY_CSPEC, favoritesByCSpecString);
	}

	public static void readSetsByCSpec(
			Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> setsByCSpec, String encoded) {
		LanguageService langServ = DefaultLanguageService.getLanguageService();
		if (encoded.length() == 0) {
			return;
		}
		String[] cSpecRegPairParts = encoded.split(";");
		for (String pairPart : cSpecRegPairParts) {
			String[] parts = pairPart.split(":");
			if (parts.length < 2) {
				Msg.warn(DebuggerRegistersPlugin.class, "Bad cspec-regs entry: " +
					pairPart.substring(0, Math.min(10, pairPart.length())) + ". Ignoring.");
				continue;
			}
			String langCsPart = StringUtils.join(parts, ':', 0, parts.length - 1);
			String regsPart = parts[parts.length - 1];
			String[] langCsParts = langCsPart.split("/");
			if (langCsParts.length != 2) {
				Msg.warn(DebuggerRegistersPlugin.class,
					"Bad lang-spec key: " + langCsPart + ". Ignoring.");
				continue;
			}
			LanguageID lid = new LanguageID(langCsParts[0]);
			Language lang;
			try {
				lang = langServ.getLanguage(lid);
			}
			catch (LanguageNotFoundException e) {
				Msg.warn(DebuggerRegistersPlugin.class,
					"Language " + langCsParts[0] + " does not exist. Ignoring.");
				continue;
			}
			CompilerSpecID csid = new CompilerSpecID(langCsParts[1]);

			LinkedHashSet<Register> regs = new LinkedHashSet<>();
			for (String regName : regsPart.split(",")) {
				Register register = lang.getRegister(regName);
				if (register == null) {
					Msg.warn(DebuggerRegistersPlugin.class,
						"Register " + regName + " does not exist. Ignoring.");
					continue;
				}
				regs.add(register);
			}

			setsByCSpec.put(new LanguageCompilerSpecPair(lid, csid), regs);
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String selectionByCSpecString = saveState.getString(KEY_SELECTION_BY_CSPEC, "");
		readSetsByCSpec(selectionByCSpec, selectionByCSpecString);
		String favoritesByCSpecString = saveState.getString(KEY_FAVORITES_BY_CSPEC, "");
		readSetsByCSpec(favoritesByCSpec, favoritesByCSpecString);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		List<DebuggerRegistersProvider> disconnected = List.copyOf(disconnectedProviders);
		saveState.putInt(KEY_DISCONNECTED_COUNT, disconnected.size());
		for (int index = 0; index < disconnected.size(); index++) {
			DebuggerRegistersProvider provider = disconnected.get(index);
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			SaveState providerState = new SaveState();
			provider.writeDataState(providerState);
			saveState.putXmlElement(stateName, providerState.saveToXml());
		}
	}

	@Override
	public void readDataState(SaveState saveState) {
		int disconnectedCount = saveState.getInt(KEY_DISCONNECTED_COUNT, 0);
		while (disconnectedProviders.size() < disconnectedCount) {
			createNewDisconnectedProvider();
		}
		while (disconnectedProviders.size() > disconnectedCount) {
			disconnectedProviders.iterator().next().removeFromTool();
		}

		List<DebuggerRegistersProvider> disconnected = List.copyOf(disconnectedProviders);

		for (int index = 0; index < disconnectedCount; index++) {
			String stateName = PREFIX_DISCONNECTED_PROVIDER + index;
			Element providerElement = saveState.getXmlElement(stateName);
			if (providerElement != null) {
				SaveState providerState = new SaveState(providerElement);
				DebuggerRegistersProvider provider = disconnected.get(index);
				provider.readDataState(providerState);
			}
		}
	}
}
