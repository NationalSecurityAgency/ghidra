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
package generic.timer;

import ghidra.util.SystemUtilities;

public class GhidraTimerFactory {
	public static GhidraTimer getGhidraTimer(int initialDelay, int delay, TimerCallback callback) {
		if (SystemUtilities.isInHeadlessMode()) {
			return new GhidraSwinglessTimer(initialDelay, delay, callback);
			
		}
		return new GhidraSwingTimer(initialDelay, delay, callback);
	}
	
	public static void main(String[] args) throws InterruptedException {
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");
		final GhidraTimer t = GhidraTimerFactory.getGhidraTimer(500,500,null);
		t.setDelay(500);
		TimerCallback callback1 = new TimerCallback() {
			int i = 0;
			public void timerFired() {
				System.out.println("A: "+i);
				if (++i == 20) {
					t.stop();
				}
			}
		};
		t.setTimerCallback(callback1);
		t.start();
		
		final GhidraTimer t2 = GhidraTimerFactory.getGhidraTimer(250, 1000, null);
		
		TimerCallback callback2 = new TimerCallback() {
			int i = 0;
			public void timerFired() {
				System.out.println("B: "+i);
				if (++i == 100) {
					t2.stop();
				}
			}
		};
		t2.setInitialDelay(250);
		t2.setTimerCallback(callback2);
		t2.start();

		
		
		Thread.sleep(20000);

	}
}
