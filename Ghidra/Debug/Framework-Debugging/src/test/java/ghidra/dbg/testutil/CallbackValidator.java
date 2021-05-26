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
package ghidra.dbg.testutil;

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;

import ghidra.dbg.*;
import ghidra.dbg.agent.AbstractTargetObject;
import ghidra.dbg.attributes.TargetObjectList;
import ghidra.dbg.attributes.TargetStringList;
import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAttacher.TargetAttachKind;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetSteppable.TargetStepKind;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

public class CallbackValidator implements DebuggerModelListener, AutoCloseable {

	protected static class CreationRecord {
		private final TargetObject object;
		private final Throwable stack;

		public CreationRecord(TargetObject object) {
			this.object = object;
			this.stack = new Throwable("Existing object created here");
		}
	}

	public CatchOffThread off = new CatchOffThread();

	public final DebuggerObjectModel model;
	public Thread thread = null;
	public Map<TargetObject, CreationRecord> valid = new HashMap<>();

	// Knobs
	// TODO: Make these methods instead?
	public boolean log = false;
	public boolean requireSameThread = true;
	public boolean requireSameModel = true;
	public boolean requireValid = true;
	public boolean requireProxy = true;
	public Set<Class<?>> allowedTypes = Set.of( // When not a TargetObject
		Boolean.class, boolean.class, Byte.class, byte.class, byte[].class, Character.class,
		char.class, Double.class, double.class, Float.class, float.class, Integer.class, int.class,
		Long.class, long.class, String.class, TargetStringList.class, Address.class,
		AddressRange.class, TargetAttachKind.class, TargetAttachKindSet.class,
		TargetBreakpointKind.class, TargetBreakpointKindSet.class, TargetStepKind.class,
		TargetStepKindSet.class, TargetExecutionState.class, TargetEventType.class,
		TargetParameterMap.class, TargetObjectList.class);

	public CallbackValidator(DebuggerObjectModel model) {
		this.model = model;
		model.addModelListener(this, true);
	}

	public void validateCallbackThread(String callback) {
		if (thread == null) {
			thread = Thread.currentThread();
		}
		if (requireSameThread) {
			assertEquals("Callback " + callback + " came from an unexpected thread", thread,
				Thread.currentThread());
		}
	}

	public void validateCompletionThread() {
		if (thread == null) {
			thread = Thread.currentThread();
		}
		if (requireSameThread) {
			assertEquals("Completion came from an unexpected thread. Probably forgot gateFuture()",
				thread, Thread.currentThread());
		}
	}

	public void validateObjectModel(String callback, TargetObject obj) {
		if (requireSameModel) {
			assertEquals("Callback " + callback + " included foreign object " + obj, model,
				obj.getModel());
		}
	}

	public void validateObjectProxy(String callback, TargetObject obj) {
		if (requireProxy && obj instanceof AbstractTargetObject<?>) {
			AbstractTargetObject<?> ato = (AbstractTargetObject<?>) obj;
			assertEquals(
				"Non-proxy object " + obj.getJoinedPath(".") + "leaked into callback " + callback,
				obj, ato.getProxy());
		}
	}

	public void validateObjectValid(String callback, TargetObject obj) {
		if (requireValid) {
			assertTrue("Object " + obj.getJoinedPath(".") + " invalid during callback " + callback,
				valid.containsKey(obj));
		}
	}

	public void validateObjectInvalid(String callback, TargetObject obj) {
		if (requireValid) {
			assertFalse("Object " + obj.getJoinedPath(".") + " valid during callback " + callback +
				", but should have been invalid", valid.containsKey(obj));
		}
	}

	public void validateInvalidObject(String callback, TargetObject obj) {
		assertNotNull(obj);
		validateObjectModel(callback, obj);
		validateObjectProxy(callback, obj);
		validateObjectInvalid(callback, obj);
	}

	public void validateObject(String callback, TargetObject obj) {
		assertNotNull(obj);
		validateObjectModel(callback, obj);
		validateObjectProxy(callback, obj);
		validateObjectValid(callback, obj);
	}

	public void validateObjectOptional(String callback, TargetObject obj) {
		if (obj != null) {
			validateObject(callback, obj);
		}
	}

	public void validateObjects(String callback, Collection<? extends TargetObject> objs) {
		for (TargetObject obj : objs) {
			validateObject(callback, obj);
		}
	}

	public void validateObjectsInMap(String callback, Map<String, ?> map) {
		for (Entry<String, ?> ent : map.entrySet()) {
			Object obj = ent.getValue();
			validateObjectOrAllowedType(callback + "(key=" + ent.getKey() + ")", obj);
		}
	}

	public void validateObjectOrAllowedType(String callback, Object obj) {
		if (obj instanceof TargetObject) {
			validateObject(callback, (TargetObject) obj);
			return;
		}
		for (Class<?> cls : allowedTypes) {
			if (cls.isInstance(obj)) {
				return;
			}
		}
		fail(
			"Invalid object type in callback " + callback + " " + obj + "(" + obj.getClass() + ")");
	}

	public void validateObjectsInCollection(String callback, Collection<?> objs) {
		for (Object obj : objs) {
			validateObjectOrAllowedType(callback, obj);
		}
	}

	@Override
	public synchronized void catastrophic(Throwable t) {
		if (log) {
			Msg.info(this, "catastrophic(t=" + t + ")");
		}
		off.catching(() -> {
			throw new AssertionError("Catastrophic error", t);
		});
	}

	@Override
	public void modelClosed(DebuggerModelClosedReason reason) {
		if (log) {
			Msg.info(this, "modelClosed(reason=" + reason + ")");
		}
	}

	@Override
	public synchronized void elementsChanged(TargetObject object, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		if (log) {
			Msg.info(this, "elementsChanged(object=" + object + ",removed=" + removed + ",added=" +
				added + ")");
		}
		off.catching(() -> {
			validateCallbackThread("elementsChanged");
			validateObject("elementsChanged.object", object);
			validateObjectsInMap("elementsChanged.added(object=" + object.getJoinedPath(".") + ")",
				added);
		});
	}

	@Override
	public synchronized void attributesChanged(TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
		if (log) {
			Msg.info(this, "attributesChanged(object=" + object + ",removed=" + removed +
				",added=" + added + ")");
		}
		off.catching(() -> {
			validateCallbackThread("attributesChanged");
			validateObject("attributesChanged.object", object);
			validateObjectsInMap(
				"attributesChanged.added(object=" + object.getJoinedPath(".") + ")", added);
		});
	}

	@Override
	public synchronized void breakpointHit(TargetObject container, TargetObject trapped,
			TargetStackFrame frame, TargetBreakpointSpec spec,
			TargetBreakpointLocation breakpoint) {
		if (log) {
			Msg.info(this, "breakpointHit(container=" + container + ",trapped=" + trapped +
				",frame=" + frame + ",spec=" + spec + ",breakpoint=" + breakpoint + ")");
		}
		off.catching(() -> {
			validateCallbackThread("breakpointHit");
			validateObject("breakpointHit.container", container);
			validateObject("breakpointHit.trapped", trapped);
			validateObjectOptional("breakpointHit.frame", frame);
			validateObject("breakpointHit.spec", spec);
			validateObject("breakpointHit.breakpoint", breakpoint);
		});
	}

	@Override
	public synchronized void consoleOutput(TargetObject console, Channel channel, byte[] data) {
		if (log) {
			Msg.info(this, "consoleOutput(console=" + console + ",channel=" + channel + ",data=" +
				new String(data) + ")");
		}
		off.catching(() -> {
			validateCallbackThread("consoleOutput");
			validateObject("consoleOutput", console);
			assertNotNull(data);
		});
	}

	@Override
	public synchronized void created(TargetObject object) {
		if (log) {
			Msg.info(this, "created(object=" + object + ")");
		}
		CreationRecord record = new CreationRecord(object);
		CreationRecord exists = valid.put(object, record);
		off.catching(() -> {
			if (exists != null) {
				Msg.error(this, "Original creation: ", exists.stack);
				Msg.error(this, "New creation: ", record.stack);
				if (exists.object == object) {
					fail("created twice (same object): " + object.getJoinedPath("."));
				}
				else {
					fail("replaced before invalidation. old=" + exists.object + ", new=" + object);
				}
			}
			validateCallbackThread("created");
			validateObject("created", object);
		});
	}

	@Override
	public synchronized void event(TargetObject object, TargetThread eventThread,
			TargetEventType type, String description, List<Object> parameters) {
		if (log) {
			Msg.info(this, "event(object=" + object + ",eventThread=" + eventThread + ",type=" +
				type + ",description=" + description + ",parameters=" + parameters + ")");
		}
		off.catching(() -> {
			validateCallbackThread("event(" + type + ")");
			validateObject("event(" + type + ")", object);
			if (type == TargetEventType.THREAD_CREATED || type == TargetEventType.THREAD_EXITED) {
				validateObject("event(" + type + ")", eventThread);
			}
			else {
				validateObjectOptional("event(" + type + ").eventThread", eventThread);
			}
			assertNotNull(type);
			assertNotNull(description);
			validateObjectsInCollection("event(" + type + ").parameters", parameters);
		});
	}

	@Override
	public synchronized void invalidateCacheRequested(TargetObject object) {
		if (log) {
			Msg.info(this, "invalidateCacheRequested(object=" + object + ")");
		}
		off.catching(() -> {
			validateCallbackThread("invalidateCacheRequested");
			validateObject("invalidateCacheRequested", object);
		});
	}

	@Override
	public synchronized void invalidated(TargetObject object, TargetObject branch, String reason) {
		if (log) {
			Msg.info(this,
				"invalidated(object=" + object + ",branch=" + branch + ",reason=" + reason + ")");
		}
		off.catching(() -> {
			validateCallbackThread("invalidated");
			validateObject("invalidated", object);
			valid.remove(object);
			validateInvalidObject("invalidated", branch); // pre-ordered callbacks
			assertNotNull(reason);
		});
	}

	@Override
	public synchronized void memoryReadError(TargetObject memory, AddressRange range,
			DebuggerMemoryAccessException e) {
		if (log) {
			Msg.info(this,
				"memoryReadError(memory=" + memory + ",range=" + range + ",e=" + e + ")");
		}
		off.catching(() -> {
			validateCallbackThread("memoryReadError");
			validateObject("memoryReadError", memory);
			assertNotNull(range);
			throw new AssertionError("Memory read error", e);
		});
	}

	@Override
	public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
		if (log) {
			Msg.info(this, "memoryUpdated(memory=" + memory + ",address=" + address + ",data=" +
				NumericUtilities.convertBytesToString(data) + ")");
		}
		off.catching(() -> {
			validateCallbackThread("memoryUpdated");
			validateObject("memoryUpdated", memory);
			assertNotNull(address);
			// TODO: Validate address for regions
			assertNotNull(data);
		});
	}

	@Override
	public void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
		if (log) {
			Msg.info(this, "registersUpdated(bank=" + bank + ",updates=" +
				DebuggerModelTestUtils.hexlify(updates) + ")");
		}
		off.catching(() -> {
			validateCallbackThread("registersUpdated");
			validateObject("registersUpdated", bank);
			assertNotNull(updates);
			// TODO: Validate names to descriptions, including lengths of values
		});
	}

	@Override
	public void rootAdded(TargetObject root) {
		if (log) {
			Msg.info(this, "rootAdded(root=" + root + ")");
		}
		off.catching(() -> {
			validateCallbackThread("rootAdded");
			validateObject("rootAdded", root);
		});
	}

	@Override
	public synchronized void close() throws Exception {
		off.close();
	}
}
