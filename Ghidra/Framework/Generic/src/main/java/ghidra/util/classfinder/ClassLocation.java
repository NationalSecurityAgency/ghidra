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
package ghidra.util.classfinder;

import java.util.List;
import java.util.HashSet;
import java.util.Set;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a place from which {@link Class}s can be obtained
 */
abstract class ClassLocation {

	public static final String CLASS_EXT = ".class";
	private Thread td;
	protected Set<ClassFileInfo> classes = new HashSet<>();
	protected List<ClassFileInfo> dest;
	
	protected ClassLocation(List<ClassFileInfo> dest) {
		this.dest = dest;
	}
	
	protected void start(TaskMonitor monitor) {
		td = Thread.ofVirtual().start(() -> scanInBackground(monitor));
	}
	
	private void scanInBackground(TaskMonitor monitor) {
		try {
			scan(monitor);
			synchronized (dest) {
				dest.addAll(classes);
			}
		}
		catch (CancelledException e) {
		}
	}
	
	protected abstract void scan(TaskMonitor monitor) throws CancelledException;

	final void join(TaskMonitor monitor) throws CancelledException {
		while (true) {
			try {
				td.join();
				break;
			}
			catch (InterruptedException e) {
			}
			monitor.checkCancelled();
		}
	}
}
