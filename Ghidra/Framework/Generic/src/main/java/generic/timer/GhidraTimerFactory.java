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
package generic.timer;

import java.util.Timer;

import ghidra.util.SystemUtilities;
import ghidra.util.timer.GTimer;

/**
 * Creates a new {@link GhidraTimer} appropriate for a headed or headless environment.
 * <P>
 * If running a headed environment, the callback will happen on the Swing thread.  Otherwise, the
 * callback will happen on the non-Swing {@link Timer} thread.
 * <P>
 * See also {@link GTimer}
 */
public class GhidraTimerFactory {
	public static GhidraTimer getGhidraTimer(int initialDelay, int delay, TimerCallback callback) {
		if (SystemUtilities.isInHeadlessMode()) {
			return new GhidraSwinglessTimer(initialDelay, delay, callback);

		}
		return new GhidraSwingTimer(initialDelay, delay, callback);
	}
}
