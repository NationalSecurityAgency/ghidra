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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.*;
import java.util.function.Function;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.util.Msg;

public class EventValidator
		implements DebuggerModelListener, AutoCloseable, DebuggerModelTestUtils {
	public CatchOffThread off = new CatchOffThread();

	interface Observation {
		String getEvent();

		TargetObject getObject();

		Observation inParameter(String event);

		default Observation inAncestor(String event, TargetObject successor) {
			return inParameter("Parent of " + successor.getJoinedPath(".") + " in " + event);
		}

		Observation inCreated(String event);

		Observation inDestroyed(String event);
	}

	static abstract class AbstractObservation implements Observation {
		private final String event;
		private final TargetObject object;

		public AbstractObservation(String event, TargetObject object) {
			this.event = event;
			this.object = object;
		}

		@Override
		public String getEvent() {
			return event;
		}

		@Override
		public TargetObject getObject() {
			return object;
		}

		protected String getPath() {
			return object.getJoinedPath(".");
		}
	}

	static class NoObservation extends AbstractObservation {
		public NoObservation(TargetObject object) {
			super("[none]", object);
		}

		@Override
		public Observation inParameter(String event) {
			return new UseObservation(event, getObject());
		}

		@Override
		public Observation inCreated(String event) {
			return new CreatedObservation(event, getObject());
		}

		@Override
		public Observation inDestroyed(String event) {
			return new DestroyedObservation(event, getObject());
		}
	}

	static class UseObservation extends AbstractObservation {
		public UseObservation(String event, TargetObject object) {
			super(event, object);
		}

		@Override
		public Observation inParameter(String event) {
			return this;
		}

		@Override
		public Observation inCreated(String event) {
			throw new AssertionError(
				"Observed " + getEvent() + " for " + getPath() + " before " + event);
		}

		@Override
		public Observation inDestroyed(String event) {
			return new DestroyedObservation(event, getObject());
		}
	}

	static class CreatedObservation extends AbstractObservation {
		public CreatedObservation(String event, TargetObject object) {
			super(event, object);
		}

		@Override
		public Observation inParameter(String event) {
			return this;
		}

		@Override
		public Observation inCreated(String event) {
			throw new AssertionError("Observed double-" + event + " of " + getPath());
		}

		@Override
		public Observation inDestroyed(String event) {
			return new DestroyedObservation(event, getObject());
		}
	}

	static class DestroyedObservation extends AbstractObservation {
		public DestroyedObservation(String event, TargetObject object) {
			super(event, object);
		}

		@Override
		public Observation inParameter(String event) {
			throw new AssertionError(
				"Observed " + event + " of " + getPath() + " after " + getEvent());
		}

		@Override
		public Observation inCreated(String event) {
			return new CreatedObservation(event, getObject());
		}

		@Override
		public Observation inDestroyed(String event) {
			throw new AssertionError("Observed double-" + event + " of " + getPath());
		}
	}

	public final DebuggerObjectModel model;
	public Map<TargetProcess, Observation> processes = new HashMap<>();
	public Map<TargetThread, Observation> threads = new HashMap<>();
	public Map<TargetModule, Observation> modules = new HashMap<>();

	// Knobs
	public boolean log = false;

	public EventValidator(DebuggerObjectModel model) {
		this.model = model;
		model.addModelListener(this);
	}

	@Override
	public void invalidated(TargetObject object, TargetObject branch, String reason) {
		if (log) {
			Msg.info(this,
				"invalidated(object=" + object + ",branch=" + branch + ",reason=" + reason + ")");
		}
		processes.remove(object);
		threads.remove(object);
		modules.remove(object);
	}

	@Override
	public synchronized void event(TargetObject object, TargetThread eventThread,
			TargetEventType type, String description, List<Object> parameters) {
		if (log) {
			Msg.info(this,
				"event(object=" + object + ",eventThread=" + eventThread + ",type=" + type +
					",description=" + description + ",parameters=" + parameters + ")");
		}
		off.catching(() -> {
			switch (type) {
				case PROCESS_CREATED:
					validateCreated(type.name(), TargetProcess.class, processes, parameters);
					break;
				case PROCESS_EXITED:
					validateDestroyed(type.name(), TargetProcess.class, processes, parameters);
					break;
				case THREAD_CREATED:
					validateCreated(type.name(), TargetThread.class, threads, parameters);
					break;
				case THREAD_EXITED:
					validateDestroyed(type.name(), TargetThread.class, threads, parameters);
					break;
				case MODULE_LOADED:
					validateCreated(type.name(), TargetModule.class, modules, parameters);
					break;
				case MODULE_UNLOADED:
					validateDestroyed(type.name(), TargetModule.class, modules, parameters);
					break;
				case STOPPED:
				case RUNNING:
				case BREAKPOINT_HIT:
				case STEP_COMPLETED:
				case EXCEPTION:
				case SIGNAL:
					validateParameters(type.name(), parameters);
					break;
				default:
					fail("Unexpected event type");
			}
		});
	}

	protected <T extends TargetObject> void observe(Map<T, Observation> map, T object,
			Function<Observation, Observation> func) {
		map.compute(object, (__, observation) -> {
			if (observation == null) {
				observation = new NoObservation(object);
			}
			return func.apply(observation);
		});
	}

	protected void validateParameters(String event, List<Object> objects) {
		for (Object obj : objects) {
			if (obj instanceof TargetProcess) {
				observe(processes, (TargetProcess) obj, o -> o.inParameter(event));
			}
			if (obj instanceof TargetThread) {
				observe(threads, (TargetThread) obj, o -> o.inParameter(event));
			}
			if (obj instanceof TargetModule) {
				observe(modules, (TargetModule) obj, o -> o.inParameter(event));
			}
		}
	}

	protected void validateAncestors(String event, TargetObject object) {
		TargetObject ancestor = object;
		while (null != (ancestor = ancestor.getParent())) { // Yes, pre-step to parent
			if (ancestor instanceof TargetProcess) {
				observe(processes, (TargetProcess) ancestor, o -> o.inAncestor(event, object));
			}
			if (ancestor instanceof TargetThread) {
				observe(threads, (TargetThread) ancestor, o -> o.inAncestor(event, object));
			}
			if (ancestor instanceof TargetModule) {
				observe(modules, (TargetModule) ancestor, o -> o.inAncestor(event, object));
			}
		}
	}

	protected <T> T doGetFirstAs(Class<T> cls, List<Object> objects) {
		if (objects.isEmpty()) {
			return null;
		}
		Object first = objects.get(0);
		if (!cls.isInstance(first)) {
			return null;
		}
		return cls.cast(first);
	}

	protected <T> T getFirstAs(String event, Class<T> cls, List<Object> objects) {
		T result = doGetFirstAs(cls, objects);
		assertNotNull("The first parameter of " + event + " must be a " + cls.getSimpleName(),
			result);
		return result;
	}

	protected <T extends TargetObject> void validateCreated(String event, Class<T> cls,
			Map<T, Observation> map, List<Object> objects) {
		T t = getFirstAs(event, cls, objects);
		observe(map, t, o -> o.inCreated(event));
		validateAncestors(event, t);
		validateParameters(event, objects.subList(1, objects.size()));
	}

	protected <T extends TargetObject> void validateDestroyed(String event, Class<T> cls,
			Map<T, Observation> map, List<Object> objects) {
		T t = getFirstAs(event, cls, objects);
		observe(map, t, o -> o.inDestroyed(event));
		validateAncestors(event, t);
		validateParameters(event, objects.subList(1, objects.size()));
	}

	@Override
	public synchronized void close() throws Exception {
		off.close();
	}
}
