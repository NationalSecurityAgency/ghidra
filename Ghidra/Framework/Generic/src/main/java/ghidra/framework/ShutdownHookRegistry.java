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
package ghidra.framework;

import java.util.TreeSet;

public class ShutdownHookRegistry {

	private static boolean hookInstalled = false;

	private static TreeSet<ShutdownHook> hooks = new TreeSet<ShutdownHook>();

	/**
	 * Install a shutdown hook at the specified priority.  If the hook has no specific 
	 * priority or sensitivity to when it runs, the standard Java Runtime shutdown hook
	 * mechanism should be used.
	 * Hooks with a higher priority value will run first
	 * @param r shutdown hook runnable
	 * @param priority relative priority
	 */
	public static synchronized ShutdownHook addShutdownHook(Runnable r, ShutdownPriority priority) {

		ShutdownHook hook = new ShutdownHook(r, priority.getPriority());
		hooks.add(hook);

		installHook();

		return hook;
	}

	/**
	 * Remove a shutdown hook previously registered.
	 * Hooks with a higher priority value will run first
	 * @param hook shutdown hook
	 */
	public static synchronized void removeShutdownHook(ShutdownHook hook) {
		hooks.remove(hook);
	}

	private static void installHook() {
		if (hookInstalled) {
			return;
		}
		Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
			public void run() {
				notifyHooks();
			}
		}, "Shutdown Hook Registry Notifier"));
		hookInstalled = true;
	}

	private static void notifyHooks() {

		for (ShutdownHook hook : hooks) {
			try {
				hook.r.run();
			}
			catch (Throwable t) {
				t.printStackTrace();
			}
		}
	}

	/**
	 * <code>ShutdownHook</code> wrapper class for shutdown callback
	 */
	public static class ShutdownHook implements Comparable<ShutdownHook> {
		Runnable r;
		int priority;

		ShutdownHook(Runnable r, int priority) {
			this.r = r;
			this.priority = priority;
		}

		@Override
		public int compareTo(ShutdownHook o) {
			return priority - o.priority;
		}

	}

}
