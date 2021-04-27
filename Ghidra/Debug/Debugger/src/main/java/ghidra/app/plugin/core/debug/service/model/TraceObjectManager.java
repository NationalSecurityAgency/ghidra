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
package ghidra.app.plugin.core.debug.service.model;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.*;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.interfaces.*;
import ghidra.app.services.TraceRecorder;
import ghidra.app.services.TraceRecorderListener;
import ghidra.async.AsyncLazyMap;
import ghidra.dbg.target.*;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.program.model.address.Address;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.DuplicateNameException;

public class TraceObjectManager {

	private final TargetObject target;
	private final TraceEventListener eventListener;
	final TraceObjectListener objectListener;

	protected final NavigableMap<List<String>, TargetObject> objects =
		new TreeMap<>(PathComparator.KEYED);

	private DefaultTraceRecorder recorder;

	private AbstractDebuggerTargetTraceMapper mapper;
	protected DebuggerMemoryMapper memMapper;
	protected AsyncLazyMap<TargetRegisterContainer, DebuggerRegisterMapper> regMappers;
	//private AbstractRecorderRegisterSet threadRegisters;

	private final ListenerSet<TraceRecorderListener> listeners =
		new ListenerSet<>(TraceRecorderListener.class);

	protected final Set<TargetBreakpointLocation> breakpoints = new HashSet<>();

	// NB: We add the objects in top-down order and initialize them bottom-up
	private LinkedHashMap<Class<?>, Function<TargetObject, Void>> handlerMapCreate =
		new LinkedHashMap<>();
	private LinkedHashMap<Class<?>, Function<TargetObject, Void>> handlerMapInit =
		new LinkedHashMap<>();
	private LinkedHashMap<Class<?>, Function<TargetObject, Void>> handlerMapRemove =
		new LinkedHashMap<>();
	private LinkedHashMap<Class<?>, BiFunction<TargetObject, Map<String, ?>, Void>> handlerMapElements =
		new LinkedHashMap<>();
	private LinkedHashMap<Class<?>, BiFunction<TargetObject, Map<String, ?>, Void>> handlerMapAttributes =
		new LinkedHashMap<>();

	public TraceObjectManager(TargetObject target, AbstractDebuggerTargetTraceMapper mapper,
			DefaultTraceRecorder recorder) {
		this.target = target;
		this.mapper = mapper;
		this.recorder = recorder;
		this.regMappers = new AsyncLazyMap<>(new HashMap<>(), ref -> mapper.offerRegisters(ref));
		//this.threadRegisters = new RecorderComposedRegisterSet(recorder);
		defaultHandlers();
		this.eventListener = new TraceEventListener(this);
		this.objectListener = new TraceObjectListener(this);
		//objectListener.addListenerAndConsiderSuccessors(target);
	}

	public void init() {
		objectListener.init();
		eventListener.init();
	}

	private void defaultHandlers() {
		putCreateHandler(TargetThread.class, this::createThread);
		putCreateHandler(TargetMemory.class, this::createMemory);
		putCreateHandler(TargetRegister.class, this::createRegister);

		putInitHandler(TargetStack.class, this::addStack);
		putInitHandler(TargetStackFrame.class, this::addStackFrame);
		putInitHandler(TargetRegisterBank.class, this::addRegisterBank);
		putInitHandler(TargetRegisterContainer.class, this::addRegisterContainer);
		//putInitHandler(TargetMemoryRegion.class, this::addMemoryRegion);
		putInitHandler(TargetModule.class, this::addModule);
		//putInitHandler(TargetSection.class, this::addSection);  // This is brutally expensive
		putInitHandler(TargetBreakpointSpecContainer.class, this::addBreakpointContainer);
		putInitHandler(TargetBreakpointSpec.class, this::addBreakpointSpec);
		putInitHandler(TargetBreakpointLocation.class, this::addBreakpointLocation);

		putElementsHandler(TargetBreakpointLocationContainer.class,
			this::elementsChangedBreakpointLocationContainer);
		putElementsHandler(TargetMemory.class, this::elementsChangedMemory);
		putElementsHandler(TargetSectionContainer.class, this::elementsChangedSectionContainer);
		putElementsHandler(TargetStack.class, this::elementsChangedStack);

		putAttributesHandler(TargetBreakpointSpec.class, this::attributesChangedBreakpointSpec);
		putAttributesHandler(TargetBreakpointLocation.class,
			this::attributesChangedBreakpointLocation);
		putAttributesHandler(TargetMemoryRegion.class, this::attributesChangedMemoryRegion);
		putAttributesHandler(TargetRegister.class, this::attributesChangedRegister);
		putAttributesHandler(TargetStackFrame.class, this::attributesChangedStackFrame);
		putAttributesHandler(TargetThread.class, this::attributesChangedThread);

		putRemHandler(TargetProcess.class, this::removeProcess);
		putRemHandler(TargetThread.class, this::removeThread);
		putRemHandler(TargetStack.class, this::removeStack);
		putRemHandler(TargetStackFrame.class, this::removeStackFrame);
		putRemHandler(TargetStack.class, this::removeRegisterBank);
		putRemHandler(TargetRegisterContainer.class, this::removeRegisterContainer);
		putRemHandler(TargetRegister.class, this::removeRegister);
		putRemHandler(TargetMemory.class, this::removeMemory);
		putRemHandler(TargetMemoryRegion.class, this::removeMemoryRegion);
		putRemHandler(TargetModule.class, this::removeModule);
		putRemHandler(TargetSection.class, this::removeSection);
		putRemHandler(TargetBreakpointSpecContainer.class, this::removeBreakpointContainer);
		putRemHandler(TargetBreakpointSpec.class, this::removeBreakpointSpec);
		putRemHandler(TargetBreakpointLocation.class, this::removeBreakpointLocation);
	}

	private <U extends TargetObject> Function<TargetObject, Void> putHandler(Class<?> key,
			Consumer<TargetObject> handler,
			LinkedHashMap<Class<?>, Function<TargetObject, Void>> handlerMap) {
		return handlerMap.put(key, (u) -> {
			handler.accept(u);
			return null;
		});
	}

	private <U extends TargetObject> BiFunction<TargetObject, Map<String, ?>, Void> putHandler(
			Class<?> key, BiConsumer<TargetObject, Map<String, ?>> handler,
			LinkedHashMap<Class<?>, BiFunction<TargetObject, Map<String, ?>, Void>> handlerMap) {
		return handlerMap.put(key, (u, v) -> {
			handler.accept(u, v);
			return null;
		});
	}

	public <U extends TargetObject> Function<TargetObject, Void> putCreateHandler(Class<?> key,
			Consumer<TargetObject> handler) {
		return putHandler(key, handler, handlerMapCreate);
	}

	public <U extends TargetObject> Function<TargetObject, Void> putInitHandler(Class<?> key,
			Consumer<TargetObject> handler) {
		return putHandler(key, handler, handlerMapInit);
	}

	public <U extends TargetObject> Function<TargetObject, Void> putRemHandler(Class<?> key,
			Consumer<TargetObject> handler) {
		return putHandler(key, handler, handlerMapRemove);
	}

	public <U extends TargetObject> BiFunction<TargetObject, Map<String, ?>, Void> putAttributesHandler(
			Class<?> key, BiConsumer<TargetObject, Map<String, ?>> handler) {
		return putHandler(key, handler, handlerMapAttributes);
	}

	public <U extends TargetObject> BiFunction<TargetObject, Map<String, ?>, Void> putElementsHandler(
			Class<?> key, BiConsumer<TargetObject, Map<String, ?>> handler) {
		return putHandler(key, handler, handlerMapElements);
	}

	private void processObject(TargetObject targetObject,
			LinkedHashMap<Class<?>, Function<TargetObject, Void>> handlerMap) {
		Set<Class<? extends TargetObject>> interfaces = targetObject.getSchema().getInterfaces();
		for (Class<? extends TargetObject> ifc : interfaces) {
			Function<TargetObject, ? extends Void> function = handlerMap.get(ifc);
			if (function != null) {
				function.apply(targetObject);
			}
		}
	}

	private void processObject(TargetObject targetObject, Map<String, ?> map,
			LinkedHashMap<Class<?>, BiFunction<TargetObject, Map<String, ?>, Void>> handlerMap) {
		Set<Class<? extends TargetObject>> interfaces = targetObject.getSchema().getInterfaces();
		for (Class<? extends TargetObject> ifc : interfaces) {
			BiFunction<TargetObject, Map<String, ?>, ? extends Void> function = handlerMap.get(ifc);
			if (function != null) {
				function.apply(targetObject, map);
			}
		}
	}

	public void createObject(TargetObject toInit) {
		processObject(toInit, handlerMapCreate);
	}

	public void initObject(TargetObject added) {
		//System.err.println("initObject " + added);
		processObject(added, handlerMapInit);
	}

	public void removeObject(TargetObject removed) {
		processObject(removed, handlerMapRemove);
	}

	public void attributesChanged(TargetObject changed, Map<String, ?> added) {
		processObject(changed, added, handlerMapAttributes);
	}

	public void elementsChanged(TargetObject changed, Map<String, ?> added) {
		processObject(changed, added, handlerMapElements);
	}

	public boolean isRequired(TargetObject obj) {
		if (obj.getName().equals("Debug"))
			return true;
		if (obj.getName().equals("Stack"))
			return true;

		Set<Class<? extends TargetObject>> interfaces = obj.getSchema().getInterfaces();
		for (Class<? extends TargetObject> ifc : interfaces) {
			if (handlerMapInit.keySet().contains(ifc)) {
				return true;
			}
		}
		return false;
	}

	public void addProcess(TargetObject added) {
		// Create a new processRecorder
		recorder.init();
	}

	public void removeProcess(TargetObject removed) {
		recorder.stopRecording();
	}

	public void createThread(TargetObject added) {
		//System.err.println("createThread " + added + ":" + this);
		synchronized (recorder.threadMap) {
			ManagedThreadRecorder threadRecorder = recorder.getThreadRecorder((TargetThread) added);
			TraceThread traceThread = threadRecorder.getTraceThread();
			recorder.createSnapshot(traceThread + " started", traceThread, null);
			try (UndoableTransaction tid =
				UndoableTransaction.start(recorder.getTrace(), "Adjust thread creation", true)) {
				traceThread.setCreationSnap(recorder.getSnap());
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e); // Should be shrinking
			}
		}
	}

	public void removeThread(TargetObject removed) {
		synchronized (recorder.threadMap) {
			ManagedThreadRecorder threadRecorder =
				recorder.getThreadRecorder((TargetThread) removed);
			threadRecorder.objectRemoved(removed);
		}
	}

	public void addStack(TargetObject added) {
		//addEventListener(added);
	}

	public void removeStack(TargetObject removed) {
		// Nothing for now
	}

	public void addStackFrame(TargetObject added) {
		ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(added);
		if (rec == null) {
			Msg.error(this, "Frame without thread?: " + added);
		}
		else {
			rec.getStackRecorder().offerStackFrame((TargetStackFrame) added);
		}
	}

	public void removeStackFrame(TargetObject removed) {
		synchronized (recorder.threadMap) {
			ManagedThreadRecorder threadRecorder = recorder.getThreadRecorderForSuccessor(removed);
			threadRecorder.objectRemoved(removed);
		}
	}

	public void addRegisterBank(TargetObject added) {
		ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(added);
		if (added instanceof TargetStackFrame) {
			rec.getStackRecorder().offerStackFrame((TargetStackFrame) added);
		}
		rec.offerRegisters((TargetRegisterBank) added);
	}

	public void removeRegisterBank(TargetObject removed) {
		//ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(removed);
		//rec.removeRegisters((TargetRegisterBank) removed);
	}

	public void addRegisterContainer(TargetObject added) {
		// These are picked up when a bank is added with these descriptions
	}

	public void removeRegisterContainer(TargetObject removed) {
		regMappers.remove((TargetRegisterContainer) removed);
	}

	public void createRegister(TargetObject added) {
		if (added.getCachedAttribute(TargetRegister.CONTAINER_ATTRIBUTE_NAME) != null) {
			TargetRegister register = (TargetRegister) added;
			regMappers.get(register.getContainer()).thenAccept(rm -> {
				if (rm != null) {
					rm.targetRegisterAdded(register);
					for (ManagedThreadRecorder rec : recorder.threadMap.byTargetThread.values()) {
						rec.regMapperAmended(rm, register, false);
					}
				}
			});
		}
	}

	public void removeRegister(TargetObject removed) {
		TargetRegister register = (TargetRegister) removed;
		TargetRegisterContainer cont = register.getContainer();
		DebuggerRegisterMapper rm = regMappers.getCompletedMap().get(cont);
		if (rm == null) {
			return;
		}
		rm.targetRegisterRemoved(register);
		for (ManagedThreadRecorder rec : recorder.threadMap.byTargetThread.values()) {
			rec.regMapperAmended(rm, register, true);
		}
	}

	public void createMemory(TargetObject added) {
		if (memMapper != null) {
			return;
		}
		mapper.offerMemory((TargetMemory) added).thenAccept(mm -> {
			synchronized (this) {
				memMapper = mm;
				//addEventListener(added);
			}
			//listenerForRecord.retroOfferMemMapperDependents();
		}).exceptionally(ex -> {
			Msg.error(this, "Could not intialize memory mapper", ex);
			return null;
		});
	}

	public void removeMemory(TargetObject removed) {
		// Nothing for now
	}

	public void addMemoryRegion(TargetObject added) {
		/*
		TargetMemoryRegion region = (TargetMemoryRegion) added;
		findThreadOrProcess(added).thenAccept(obj -> {
			if (obj == target) {
				recorder.memoryRecorder.offerProcessRegion(region);
				return;
			}
			if (obj instanceof TargetThread) {
				ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(added);
				rec.offerThreadRegion(region);
			}
		}).exceptionally(ex -> {
			Msg.error(this, "Error recording memory region", ex);
			return null;
		});
		*/
	}

	public void removeMemoryRegion(TargetObject removed) {
		recorder.memoryRecorder.removeProcessRegion((TargetMemoryRegion) removed);
	}

	public void addModule(TargetObject added) {
		recorder.moduleRecorder.offerProcessModule((TargetModule) added);
	}

	public void removeModule(TargetObject removed) {
		recorder.moduleRecorder.removeProcessModule((TargetModule) removed);
	}

	public void addSection(TargetObject added) {
		/*
		TargetSection section = (TargetSection) added;
		TargetModule module = section.getModule();
		recorder.moduleRecorder.offerProcessModuleSection(module, section);
		// I hope this should never be a per-thread thing
		*/
	}

	public void removeSection(TargetObject removed) {
		// Nothing for now
	}

	public void addBreakpointContainer(TargetObject added) {
		TargetObject obj = findThreadOrProcess(added);
		// NB. obj can be null
		ManagedBreakpointRecorder breakpointRecorder = recorder.breakpointRecorder;
		if (obj instanceof TargetThread) {
			ManagedBreakpointRecorder rec =
				recorder.getThreadRecorderForSuccessor(added).getBreakpointRecorder();
			rec.offerBreakpointContainer((TargetBreakpointSpecContainer) added);
			return;
		}
		breakpointRecorder.offerBreakpointContainer((TargetBreakpointSpecContainer) added);
	}

	public void removeBreakpointContainer(TargetObject removed) {
		// Nothing for now
	}

	public void addBreakpointSpec(TargetObject added) {
		// Nothing for now
	}

	public void removeBreakpointSpec(TargetObject removed) {
		// Nothing for now
	}

	public void addBreakpointLocation(TargetObject added) {
		// Nothing for now
		//breakpoints.add((TargetBreakpointLocation) added);
		//recorder.breakpointRecorder.offerEffectiveBreakpoint((TargetBreakpointLocation) added);
	}

	public void removeBreakpointLocation(TargetObject removed) {
		breakpoints.remove(removed);
		recorder.breakpointRecorder.removeBreakpointLocation((TargetBreakpointLocation) removed);
	}

	protected TargetObject findThreadOrProcess(TargetObject successor) {
		TargetObject object = successor;
		while (object != null) {
			if (object instanceof TargetProcess)
				return object;
			if (object instanceof TargetThread)
				return object;
			object = object.getParent();
		}
		return object;
	}

	public AbstractDebuggerTargetTraceMapper getMapper() {
		return mapper;
	}

	public DebuggerMemoryMapper getMemoryMapper() {
		return memMapper;
	}

	public AsyncLazyMap<TargetRegisterContainer, DebuggerRegisterMapper> getRegMappers() {
		return regMappers;
	}

	public Set<TargetBreakpointLocation> getBreakpoints() {
		return breakpoints;
	}

	public void attributesChangedBreakpointSpec(TargetObject bpt, Map<String, ?> added) {
		if (added.containsKey(TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME) ||
			added.containsKey(TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME)) {
			TargetBreakpointSpec spec = (TargetBreakpointSpec) bpt;
			boolean enabled = spec.isEnabled();
			Set<TraceBreakpointKind> traceKinds =
				TraceRecorder.targetToTraceBreakpointKinds(spec.getKinds());
			recorder.breakpointRecorder.breakpointSpecChanged(spec, enabled, traceKinds);
		}
	}

	public void attributesChangedBreakpointLocation(TargetObject obj, Map<String, ?> added) {
		TargetBreakpointLocation loc = (TargetBreakpointLocation) obj;
		if (added.containsKey(TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME) ||
			added.containsKey(TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME)) {
			Address traceAddr = recorder.getMemoryMapper().targetToTrace(loc.getAddress());
			String path = loc.getJoinedPath(".");
			int length = loc.getLengthOrDefault(1);
			recorder.breakpointRecorder.breakpointLocationChanged(length, traceAddr, path);
		}
	}

	public void attributesChangedMemoryRegion(TargetObject region, Map<String, ?> added) {
		if (added.containsKey(TargetObject.DISPLAY_ATTRIBUTE_NAME)) {
			recorder.memoryRecorder.regionChanged((TargetMemoryRegion) region, region.getDisplay());
		}
	}

	public void attributesChangedRegister(TargetObject parent, Map<String, ?> added) {
		if (added.containsKey(TargetRegister.CONTAINER_ATTRIBUTE_NAME)) {
			TargetRegister register = (TargetRegister) parent;
			regMappers.get(register.getContainer()).thenAccept(rm -> {
				rm.targetRegisterAdded(register);
				for (ManagedThreadRecorder rec : recorder.threadMap.byTargetThread.values()) {
					rec.regMapperAmended(rm, register, false);
				}
			});
		}
		if (added.containsKey(TargetObject.VALUE_ATTRIBUTE_NAME)) {
			TargetRegister register = (TargetRegister) parent;
			String valstr = (String) added.get(TargetObject.VALUE_ATTRIBUTE_NAME);
			byte[] value = new BigInteger(valstr, 16).toByteArray();
			ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(register);
			rec.recordRegisterValue(register, value);
		}
	}

	public void attributesChangedStackFrame(TargetObject frame, Map<String, ?> added) {
		if (added.containsKey(TargetStackFrame.PC_ATTRIBUTE_NAME)) {
			ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(frame);
			if (rec != null) {
				rec.getStackRecorder().offerStackFrame((TargetStackFrame) frame);
			}
		}
	}

	public void attributesChangedThread(TargetObject thread, Map<String, ?> added) {
		if (added.containsKey(TargetObject.DISPLAY_ATTRIBUTE_NAME)) {
			ManagedThreadRecorder rec = recorder.getThreadRecorderForSuccessor(thread);
			if (rec != null) {
				String name = (String) added.get(TargetObject.DISPLAY_ATTRIBUTE_NAME);
				try (UndoableTransaction tid =
					UndoableTransaction.start(rec.getTrace(), "Renamed thread", true)) {
					rec.getTraceThread().setName(name);
				}
			}
		}
	}

	public void elementsChangedBreakpointLocationContainer(TargetObject locationContainer,
			Map<String, ?> added) {
		TargetObject x = findThreadOrProcess(locationContainer);
		if (x != null) {
			for (Entry<String, ?> entry : added.entrySet()) {
				TargetBreakpointLocation loc = (TargetBreakpointLocation) entry.getValue();
				if (loc.isValid()) {
					breakpoints.add(loc);
					recorder.breakpointRecorder.offerBreakpointLocation(x, loc);
				}
			}
		}
	}

	public void elementsChangedMemory(TargetObject memory, Map<String, ?> added) {
		// TODO: This should probably only ever be a process
		TargetObject threadOrProcess = findThreadOrProcess(memory);
		if (threadOrProcess != null) {
			for (Object object : added.values()) {
				TargetMemoryRegion region = (TargetMemoryRegion) object;
				if (!region.isValid()) {
					continue;
				}
				if (threadOrProcess == target) {
					recorder.memoryRecorder.offerProcessRegion(region);
				}
				else if (threadOrProcess instanceof TargetThread) {
					ManagedThreadRecorder rec =
						recorder.getThreadRecorderForSuccessor(threadOrProcess);
					rec.offerThreadRegion(region);
				}
			}
		}
		else {
			Msg.error(this, "Could not find process/thread for " + memory);
		}
	}

	public void elementsChangedSectionContainer(TargetObject sectionContainer,
			Map<String, ?> added) {
		for (Object object : added.values()) {
			TargetSection section = (TargetSection) object;
			if (!section.isValid()) {
				continue;
			}
			recorder.moduleRecorder.offerProcessModuleSection(section);
		}
	}

	public void elementsChangedStack(TargetObject stack, Map<String, ?> added) {
		ManagedStackRecorder rec = recorder.getThreadRecorderForSuccessor(stack).getStackRecorder();
		rec.recordStack();
	}

	public TargetMemoryRegion getTargetMemoryRegion(TraceMemoryRegion region) {
		synchronized (objects) {
			return (TargetMemoryRegion) objects.get(PathUtils.parse(region.getPath()));
		}
	}

	public TargetModule getTargetModule(TraceModule module) {
		synchronized (objects) {
			return (TargetModule) objects.get(PathUtils.parse(module.getPath()));
		}
	}

	public TargetSection getTargetSection(TraceSection section) {
		synchronized (objects) {
			return (TargetSection) objects.get(PathUtils.parse(section.getPath()));
		}
	}

	public TargetBreakpointLocation getTargetBreakpoint(TraceBreakpoint bpt) {
		synchronized (objects) {
			return (TargetBreakpointLocation) objects.get(PathUtils.parse(bpt.getPath()));
		}
	}

	public List<TargetBreakpointLocation> collectBreakpoints(TargetThread thread) {
		return getBreakpoints().stream().collect(Collectors.toList());
	}

	public void onBreakpointContainers(TargetThread thread,
			Consumer<? super TargetBreakpointSpecContainer> action) {
		if (thread == null) {
			objectListener.onProcessBreakpointContainers(action);
		}
		else {
			objectListener.onThreadBreakpointContainers(thread, action);
		}
	}

	public void onProcessBreakpointContainers(
			Consumer<? super TargetBreakpointSpecContainer> action) {
		TargetBreakpointSpecContainer breakpointContainer =
			recorder.breakpointRecorder.getBreakpointContainer();
		if (breakpointContainer == null) {
			for (TargetThread thread : recorder.getThreadsView()) {
				objectListener.onThreadBreakpointContainers(thread, action);
			}
		}
		else {
			action.accept(breakpointContainer);
		}
	}

	public void onThreadBreakpointContainers(TargetThread thread,
			Consumer<? super TargetBreakpointSpecContainer> action) {
		TargetBreakpointSpecContainer breakpointContainer =
			recorder.getThreadRecorder(thread).getBreakpointRecorder().getBreakpointContainer();
		if (breakpointContainer == null) {
			return;
		}
		action.accept(breakpointContainer);
	}

	// Needed by TraceRecorder
	public TraceEventListener getEventListener() {
		return eventListener;
	}

	public ListenerSet<TraceRecorderListener> getListeners() {
		return listeners;
	}

	public TargetObject getTarget() {
		return target;
	}

	public DefaultTraceRecorder getRecorder() {
		return recorder;
	}

	public boolean hasObject(TargetObject object) {
		return objects.containsKey(object.getPath());
	}

	public void addObject(TargetObject added) {
		objects.put(added.getPath(), added);
	}

	public void removeObject(List<String> path) {
		objects.remove(path);
	}

	public void disposeModelListeners() {
		eventListener.dispose();
		objectListener.dispose();
	}

}
