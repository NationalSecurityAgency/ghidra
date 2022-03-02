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
package agent.frida.manager.cmd;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaCommand;
import agent.frida.manager.FridaEvent;
import agent.frida.manager.evt.AbstractFridaCompletedCommandEvent;
import agent.frida.manager.evt.FridaCommandErrorEvent;

/**
 * A command queued on the frida manager
 *
 * A {@link FridaCommand} is queued by wrapping it in a {@link FridaPendingCommand} and submitting it
 * to the manager implementation's executor. This object also keep track of claimed/stolen events
 * and provides convenience methods for sifting through them.
 *
 * @param <T> the type "returned" by the command
 */
public class FridaPendingCommand<T> extends CompletableFuture<T> implements FridaCause {
	private final FridaCommand<? extends T> cmd;
	private final Set<FridaEvent<?>> evts = new LinkedHashSet<>();

	/**
	 * Wrap a command for execution
	 * 
	 * @param cmd the command
	 */
	public FridaPendingCommand(FridaCommand<? extends T> cmd) {
		this.cmd = cmd;
	}

	/**
	 * Get the command being executed
	 * 
	 * @return cmd
	 */
	public FridaCommand<? extends T> getCommand() {
		return cmd;
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
	 * This gives the command implementation the first chance to claim or steal an event
	 * 
	 * @param evt the event
	 * @return true if the command is ready to be completed
	 */
	public boolean handle(FridaEvent<?> evt) {
		return cmd.handle(evt, this);
	}

	/**
	 * Claim an event
	 * 
	 * This stores the event for later retrieval and processing.
	 * 
	 * @param evt the event
	 */
	public void claim(FridaEvent<?> evt) {
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
	public void steal(FridaEvent<?> evt) {
		claim(evt);
		evt.steal();
	}

	/**
	 * Assume a single event of particular type was claimed/stolen, and get that event
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if more than one event was claimed/stolen
	 * @throws ClassCastException if the event cannot be cast to the given type
	 */
	public <E extends FridaEvent<?>> E castSingleEvent(Class<E> cls) {
		if (evts.size() != 1) {
			throw new IllegalStateException("Command did not claim exactly one event");
		}
		return cls.cast(evts.iterator().next());
	}

	/**
	 * Find the first claimed/stolen event of a given type
	 * 
	 * @param cls the type of the event
	 * @return the event cast to the type
	 * @throws IllegalStateException if no event of the given type was claimed/stolen
	 */
	public <E extends FridaEvent<?>> E findFirstOf(Class<E> cls) {
		for (FridaEvent<?> evt : evts) {
			if (cls.isAssignableFrom(evt.getClass())) {
				return cls.cast(evt);
			}
		}
		throw new IllegalStateException("Command did not claim any " + cls);
	}

	/**
	 * Find all events claimed/stolen of a given type
	 * 
	 * @param cls the type of the events
	 * @return the list of events cast to the type
	 */
	public <E extends FridaEvent<?>> List<E> findAllOf(Class<E> cls) {
		List<E> found = new ArrayList<>();
		for (FridaEvent<?> evt : evts) {
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
	public <E extends FridaEvent<?>> E findSingleOf(Class<E> cls) {
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
	 * {@link FridaCommandErrorEvent} need not be listed. This method will handle it as a special
	 * case already. To avoid the special treatment, list it explicitly.
	 * 
	 * @param classes the completion type to accept
	 * @return the completion event, cast to the greatest common subclass
	 */
	@SafeVarargs
	public final <E extends AbstractFridaCompletedCommandEvent> E checkCompletion(
			Class<E>... classes) {
		AbstractFridaCompletedCommandEvent completion =
			findSingleOf(AbstractFridaCompletedCommandEvent.class);
		// Allow query for exact class to override error interpretation
		for (Class<E> cls : classes) {
			if (cls == completion.getClass()) {
				return cls.cast(completion);
			}
		}
		if (completion instanceof FridaCommandErrorEvent) {
			throw new FridaCommandError(completion.getInfo(), cmd);
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
