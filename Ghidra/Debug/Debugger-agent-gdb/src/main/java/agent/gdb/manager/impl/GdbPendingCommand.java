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
package agent.gdb.manager.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbCause;
import agent.gdb.manager.evt.AbstractGdbCompletedCommandEvent;
import agent.gdb.manager.evt.GdbCommandErrorEvent;
import agent.gdb.manager.impl.cmd.GdbCommandError;

/**
 * A command queued on the GDB manager
 *
 * A {@link GdbCommand} is queued by wrapping it in a {@link GdbPendingCommand} and submitting it to
 * the manager implementation's executor. This object also keep track of claimed/stolen events and
 * provides convenience methods for sifting through them.
 *
 * @param <T> the type "returned" by the command
 */
public class GdbPendingCommand<T> extends CompletableFuture<T> implements GdbCause {
	private final GdbCommand<? extends T> cmd;
	private final Set<GdbEvent<?>> evts = new LinkedHashSet<>();

	/**
	 * Wrap a command for execution
	 * 
	 * @param cmd the command
	 */
	public GdbPendingCommand(GdbCommand<? extends T> cmd) {
		this.cmd = cmd;
	}

	/**
	 * Get the command being executed
	 * 
	 * @return
	 */
	public GdbCommand<? extends T> getCommand() {
		return cmd;
	}

	public Integer impliesCurrentThreadId() {
		return cmd.impliesCurrentThreadId();
	}

	public Integer impliesCurrentFrameId() {
		return cmd.impliesCurrentFrameId();
	}

	/**
	 * Finish the execution of this command
	 */
	public void finish() {
		//Msg.trace(this, "Finishing " + cmd);
		try {
			T result = cmd.complete(this);
			complete(result);
		}
		catch (Throwable e) {
			completeExceptionally(e);
		}
	}

	/**
	 * Handle an event
	 * 
	 * <p>
	 * This gives the command implementation the first chance to claim or steal an event
	 * 
	 * @param evt the event
	 * @return true if the command is ready to be completed
	 */
	public boolean handle(GdbEvent<?> evt) {
		return cmd.handle(evt, this);
	}

	/**
	 * Claim an event
	 * 
	 * This stores the event for later retrieval and processing.
	 * 
	 * @param evt the event
	 */
	public void claim(GdbEvent<?> evt) {
		evt.claim(this);
		evts.add(evt);
	}

	/**
	 * Steal an event
	 * 
	 * This stores the event for later retrieval and processing.
	 * 
	 * @param evt the event
	 */
	public void steal(GdbEvent<?> evt) {
		claim(evt);
		evt.steal();
	}

	/**
	 * Assume a single event was claimed/stolen, and get that event as the given type
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if more than one event was claimed/stolen
	 * @throws ClassCastException if the event cannot be cast to the given type
	 */
	public <E extends GdbEvent<?>> E castSingleEvent(Class<E> cls) {
		if (evts.size() != 1) {
			throw new IllegalStateException("Command did not claim exactly one event");
		}
		return cls.cast(evts.iterator().next());
	}

	/**
	 * Get the first claimed/stolen event of a given type
	 * 
	 * @param <E> the type of the event
	 * @param cls the class of the event
	 * @return the event cast to the type, or null
	 */
	public <E extends GdbEvent<?>> E getFirstOf(Class<E> cls) {
		for (GdbEvent<?> evt : evts) {
			if (cls.isAssignableFrom(evt.getClass())) {
				return cls.cast(evt);
			}
		}
		return null;
	}

	/**
	 * Find the first claimed/stolen event of a given type
	 * 
	 * @param <E> the type of the event
	 * @param cls the class of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if no event of the given type was claimed/stolen
	 */
	public <E extends GdbEvent<?>> E findFirstOf(Class<E> cls) {
		E first = getFirstOf(cls);
		if (first != null) {
			return first;
		}
		throw new IllegalStateException("Command did not claim any " + cls);
	}

	/**
	 * Check if any event of a given type has been claimed
	 * 
	 * @param cls the class of the event
	 * @return true if at least one is claimed, false otherwise
	 */
	public boolean hasAny(Class<? extends GdbEvent<?>> cls) {
		return getFirstOf(cls) != null;
	}

	/**
	 * Find all events claimed/stolen of a given type
	 * 
	 * @param cls the type of the events
	 * @return the list of events cast to the type
	 */
	public <E extends GdbEvent<?>> List<E> findAllOf(Class<E> cls) {
		List<E> found = new ArrayList<>();
		for (GdbEvent<?> evt : evts) {
			if (cls.isAssignableFrom(evt.getClass())) {
				found.add(cls.cast(evt));
			}
		}
		return found;
	}

	/**
	 * Assume exactly one event of the given type was claimed/stolen, and get that event
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if more than one event matches
	 */
	public <E extends GdbEvent<?>> E findSingleOf(Class<E> cls) {
		List<E> found = findAllOf(cls);
		if (found.size() != 1) {
			throw new IllegalStateException(
				"Command did not claim exactly one " + cls + ". Have " + evts);
		}
		return found.get(0);
	}

	/**
	 * Check that the command completed with one of the given results
	 * 
	 * {@link GdbCommandErrorEvent} need not be listed. This method will handle it as a special case
	 * already. To avoid the special treatment, list it explicitly.
	 * 
	 * @param classes the completion type to accept
	 * @return the completion event, cast to the greatest common subclass
	 */
	@SafeVarargs
	public final <E extends AbstractGdbCompletedCommandEvent> E checkCompletion(
			Class<E>... classes) {
		AbstractGdbCompletedCommandEvent completion =
			findSingleOf(AbstractGdbCompletedCommandEvent.class);
		// Allow query for exact class to override error interpretation
		for (Class<E> cls : classes) {
			if (cls == completion.getClass()) {
				return cls.cast(completion);
			}
		}
		if (completion instanceof GdbCommandErrorEvent) {
			throw new GdbCommandError(completion.getInfo(), cmd);
		}
		for (Class<E> cls : classes) {
			if (cls.isAssignableFrom(completion.getClass())) {
				return cls.cast(completion);
			}
		}
		throw new IllegalStateException(
			"Command completed with " + completion + ", not any of " + Arrays.asList(classes));
	}

	@Override
	public String toString() {
		return super.toString() + "(" + cmd + ")";
	}
}
