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
package ghidra.app.plugin.core.debug.service.platform;

import java.util.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.DebuggerPlatformPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.services.DebuggerPlatformService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;

@PluginInfo(
	shortDescription = "Debugger platform service plugin",
	description = "Selects and manages platforms for the current focus",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
	},
	servicesProvided = {
		DebuggerPlatformService.class,
	})
public class DebuggerPlatformServicePlugin extends Plugin implements DebuggerPlatformService {

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final Map<Trace, DebuggerPlatformMapper> mappersByTrace = new HashMap<>();

	public DebuggerPlatformServicePlugin(PluginTool tool) {
		super(tool);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	@Override
	public DebuggerPlatformMapper getCurrentMapperFor(Trace trace) {
		synchronized (mappersByTrace) {
			return mappersByTrace.get(trace);
		}
	}

	@Override
	public DebuggerPlatformMapper getMapper(Trace trace, TraceObject object, long snap) {
		/**
		 * TODO: There's a chance different components fight over the current mapper. However, I
		 * suspect all nodes in a trace will yield the same offers, so perhaps I should not worry.
		 */
		DebuggerPlatformMapper mapper;
		synchronized (mappersByTrace) {
			mapper = mappersByTrace.get(trace);
			if (mapper != null && mapper.canInterpret(object, snap)) {
				return mapper;
			}
			mapper = getNewMapper(trace, object, snap);
			if (mapper == null) {
				return null;
			}
			mappersByTrace.put(trace, mapper);
		}
		mapper.addToTrace(snap);
		firePluginEvent(new DebuggerPlatformPluginEvent(getName(), trace, mapper));
		return mapper;
	}

	@Override
	public DebuggerPlatformMapper getNewMapper(Trace trace, TraceObject object, long snap) {
		if (!traceManager.getOpenTraces().contains(trace)) {
			throw new IllegalArgumentException("Trace is not opened in this tool");
		}
		for (DebuggerPlatformOffer offer : DebuggerPlatformOpinion.queryOpinions(trace, object,
			snap, false)) {
			return offer.take(tool, trace);
		}
		return null;
	}

	@Override
	public void setCurrentMapperFor(Trace trace, DebuggerPlatformMapper mapper, long snap) {
		Objects.requireNonNull(trace);
		Objects.requireNonNull(mapper);
		if (!traceManager.getOpenTraces().contains(trace)) {
			throw new IllegalArgumentException("Trace is not opened in this tool");
		}
		synchronized (mappersByTrace) {
			mappersByTrace.put(trace, mapper);
		}
		mapper.addToTrace(snap);
		firePluginEvent(new DebuggerPlatformPluginEvent(getName(), trace, mapper));
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			synchronized (mappersByTrace) {
				mappersByTrace.remove(ev.getTrace());
			}
		}
	}
}
