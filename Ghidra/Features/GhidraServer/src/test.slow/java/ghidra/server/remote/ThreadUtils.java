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
package ghidra.server.remote;

/**
 * This cannot extend GenericTestCase because GenericTestCase pulls in
 * the AWT stuff, and we don't want to do that here.
 *
 */
public class ThreadUtils {

	/**
	 * How many times larger should the arrays be to accommodate growing numbers
	 * of threads or thread groups?
	 */
	private static final int FUDGE_FACTOR = 4;

	private static boolean recurseOn(ThreadGroup threadGroup, int depth) {
		final int activeCount = threadGroup.activeCount();
		Thread[] threads = new Thread[activeCount * FUDGE_FACTOR];
		final int actualNumberOfThreads = threadGroup.enumerate(threads, false);

		for (int ii = 0; ii < actualNumberOfThreads; ++ii) {
			if (threads[ii].getName().startsWith("AWT-")) {
				return true;
			}
		}

		final int activeGroupCount = threadGroup.activeGroupCount();
		ThreadGroup[] threadGroups = new ThreadGroup[activeGroupCount * FUDGE_FACTOR];
		final int actualNumberOfThreadGroups = threadGroup.enumerate(threadGroups, false);

		for (int ii = 0; ii < actualNumberOfThreadGroups; ++ii) {
			boolean recursedValue = recurseOn(threadGroups[ii], depth + 1);
			if (recursedValue) {
				return true;
			}
		}

		return false;
	}

	public static boolean isAWTThreadPresent() {
		Thread currentThread = Thread.currentThread();
		ThreadGroup threadGroup = currentThread.getThreadGroup();
		while (threadGroup.getParent() != null) {
			threadGroup = threadGroup.getParent();
		}
		return recurseOn(threadGroup, 0);
	}
}
