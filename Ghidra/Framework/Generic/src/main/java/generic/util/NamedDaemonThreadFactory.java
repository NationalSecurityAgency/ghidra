/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.util;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/**
 * NamedDaemonThreadFactory is a thread factory which forms daemon threads
 * with a specified name prefix for the Java concurrent Executors pools.
 *
 */
public class NamedDaemonThreadFactory implements ThreadFactory {

	private final String name;
	private ThreadFactory threadFactory;

	public NamedDaemonThreadFactory(String name) {
		this.name = name;
		threadFactory = Executors.defaultThreadFactory();
	}

	@Override
	public Thread newThread(Runnable r) {
		Thread thread = threadFactory.newThread(r);
		thread.setName(name + "-" + thread.getName());
		thread.setDaemon(true);
		return thread;
	}
}
