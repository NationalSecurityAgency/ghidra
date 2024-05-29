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
package generic.concurrent;

/**
 * A means of detecting and handling reentrant conditions.
 * 
 * <p>
 * One example where this has been applied deals with updating actions upon changes in context. If,
 * in the course of determining which actions are enabled, one of the {@code isEnabled} methods
 * displays an error dialog, the Swing thread reenters its main loop while that dialog is showing,
 * but before {@code isEnabled} has returned. This can cause all sorts of unexpected behaviors.
 * Namely, a timer could fire, context could change again, etc., and the list of actions being
 * updated may also change. At worst, this could result in many exceptions being thrown, because a
 * data structure has been modified concurrently. At best, if the loop is allowed to finish, there's
 * a lot of wasted time updating actions that will never be displayed.
 * 
 * <p>
 * In that example, the loop that updates the actions would be the "guarded block." Any point at
 * which the list of actions is modified might result in "reentrant access" and should be checked.
 * 
 * <p>
 * This class provides a primitive for instrumenting, detecting, and properly reacting to such
 * conditions. For example, if the modification should not be allowed at all, the guard can throw an
 * exception at the moment of reentrant access. Alternatively, if the modification should be
 * allowed, the guard would simply set a flag, then the guarded block can check that flag and
 * terminate early.
 * 
 * <p>
 * This implementation is <em>not</em> thread safe. It is designed to check for reentrant access,
 * not concurrent access. The client must ensure that only one thread enters the guarded block or
 * calls {@link #checkAccess()} at a time. Otherwise, the behavior is undefined.
 * 
 * <pre>
 * public class ActionManager {
 * 	private final ReentryGuard&lt;Throwable&gt; reentryGuard = new ReentryGuard&lt;&gt;() {
 * 		&#64;Override
 * 		public Throwable violated(boolean nested, Throwable previous) {
 * 			if (previous != null) {
 * 				return previous;
 * 			}
 * 			return new Throwable(); // record the stack of the violation
 * 		}
 * 	};
 * 	private final List&lt;Action&gt; actions;
 * 
 * 	public void addAction(Action action) {
 * 		// Notify the guard we've committed some reentrant behavior.
 * 		// Would need to add this to anything that modifies the action list. 
 * 		reentryGuard.checkAccess();
 * 		actions.add(action);
 * 	}
 * 
 * 	public void updateActions(Context ctx) {
 * 		try (Guarded guarded = reentryGuard.enter()) {
 * 			// There is no need to create a copy, since we'll bail before the next iteration
 * 			for (Action action : actions) {
 * 				boolean enabled = action.isEnabledForContext(ctx);
 * 				if (reentryGuard.getViolation() != null) {
 * 					break; // Actions has been modified. Bail.
 * 					// NOTE: This leaves the update incomplete.
 * 					// Something has to call updateActions again.
 * 				}
 * 				actions.setEnabled(enabled);
 * 			}
 * 		}
 * 	}
 * }
 * </pre>
 * 
 * @param <T> the type used to record information about a violation. It cannot be {@link Void}.
 */
public abstract class ReentryGuard<T> {
	private final Guarded guarded = new Guarded(this);
	private boolean inGuarded;
	private T violation;

	public static class Guarded implements AutoCloseable {
		private ReentryGuard<?> guard;

		public Guarded(ReentryGuard<?> guard) {
			this.guard = guard;
		}

		@Override
		public void close() {
			guard.inGuarded = false;
		}
	}

	/**
	 * Notify the guard of entry into the guarded block
	 * 
	 * <p>
	 * This should always be used in a {@code try-with-resources} block. This will ensure that the
	 * guard is notified of exit from the guarded block, even in exceptional circumstances.
	 * 
	 * <p>
	 * NOTE: Re-entering the guarded portion is itself a violation.
	 * 
	 * @return a closeable for notifying the guard of exit from the guarded block, or null if
	 *         reentering the guarded block
	 */
	public Guarded enter() {
		if (inGuarded) {
			violation = violated(true, violation);
			return null;
		}
		inGuarded = true;
		violation = null;
		return guarded;
	}

	/**
	 * Notify the guard of access to some resource used by the guarded block
	 * 
	 * <p>
	 * If the access turns out to be reentrant, i.e., the thread's current stack includes a frame in
	 * the guarded block, this will call {@link #violated(boolean, Object)} and record the result.
	 * It can be inspected later via {@link #getViolation()}.
	 */
	public void checkAccess() {
		if (inGuarded) {
			violation = violated(false, violation);
		}
	}

	/**
	 * Record a violation
	 * 
	 * <p>
	 * This method is called if {@link #checkAccess()} or {@link #enter()} is called while already
	 * inside a guarded block. Its return value is stored for later inspection by
	 * {@link #getViolation()}. It's possible multiple violations occur within one execution of the
	 * guarded block. The previous return value of this method is provided, if that is the case. To
	 * record only the first violation, this method should just {@code return previous} when it is
	 * non-null. To record only the last violation, this method should disregard {@code previous}.
	 * To record all violations, {@code T} will need to be a collection, and this method will need
	 * to create and/or append to the collection.
	 * 
	 * @param nested true if the violation is a nested call to {@link #enter()}; false if the
	 *            violation is a call to {@link #checkAccess()}
	 * @param previous the previous return value of this method, on the occasion of multiple
	 *            violations
	 * @return the record of the violation
	 */
	protected abstract T violated(boolean nested, T previous);

	/**
	 * Retrieve a violation, if applicable
	 * 
	 * <p>
	 * Calling this method outside of a guarded block has undefined behavior.
	 * 
	 * @return the violation; or null to indicate no violation
	 */
	public T getViolation() {
		return violation;
	}

	/**
	 * Check if there is a violation
	 * 
	 * <p>
	 * This is equivalent to checking if {@link #getViolation()} returns non-null.
	 * 
	 * @return true if there is a violation.
	 */
	public boolean isViolated() {
		return violation != null;
	}
}
