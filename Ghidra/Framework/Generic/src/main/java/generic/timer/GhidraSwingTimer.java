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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Timer;

public class GhidraSwingTimer implements GhidraTimer, ActionListener {
	private Timer timer;
	private TimerCallback callback;
	
	public GhidraSwingTimer() {
		this(100, null);
	}
	
	public GhidraSwingTimer(int delay, TimerCallback callback) {
		this(delay,delay,callback);
	}
	
	public GhidraSwingTimer(int initialDelay, int delay, TimerCallback callback) {
		this.callback = callback;
		timer = new Timer(delay, this);
		timer.setInitialDelay(delay);
	}
	
	public void actionPerformed(ActionEvent e) {
		if (callback != null) {
			callback.timerFired();
		}
	}
	
	public int getDelay() {
		return timer.getDelay();
	}

	public int getInitialDelay() {
		return timer.getInitialDelay();
	}

	public boolean isRepeats() {
		return timer.isRepeats();
	}

	public void setDelay(int delay) {
		timer.setDelay(delay);
	}

	public void setInitialDelay(int initialDelay) {
		timer.setInitialDelay(initialDelay);
	}

	public void setRepeats(boolean repeats) {
		timer.setRepeats(repeats);
	}

	public void setTimerCallback(TimerCallback callback) {
		this.callback = callback;
	}

	public void start() {
		timer.start();
	}

	public void stop() {
		timer.stop();
	}

	public boolean isRunning() {
		return timer.isRunning();
	}

}
