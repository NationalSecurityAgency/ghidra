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
package ghidra.framework;

import java.util.NoSuchElementException;


public class ShutdownPriority {
		
		public static final ShutdownPriority FIRST = new ShutdownPriority(Integer.MIN_VALUE);
		
		public static final ShutdownPriority DISPOSE_DATABASES = new ShutdownPriority(Integer.MAX_VALUE / 2);
		
		public static final ShutdownPriority DISPOSE_FILE_HANDLES = new ShutdownPriority(Integer.MAX_VALUE / 2);
		
		public static final ShutdownPriority SHUTDOWN_LOGGING = new ShutdownPriority(Integer.MAX_VALUE / 2);
		
		public static final ShutdownPriority LAST = new ShutdownPriority(Integer.MAX_VALUE);
		
		private int priority;
		
		ShutdownPriority(int priority) {
			this.priority = priority;
		}
		
		public ShutdownPriority before() {
			if (priority == Integer.MIN_VALUE) {
				throw new NoSuchElementException();
			}
			return new ShutdownPriority(priority-1);
		}
		
		public ShutdownPriority after() {
			if (priority == Integer.MAX_VALUE) {
				throw new NoSuchElementException();
			}
			return new ShutdownPriority(priority+1);
		}
		
		int getPriority() {
			return priority;
		}
		
}
