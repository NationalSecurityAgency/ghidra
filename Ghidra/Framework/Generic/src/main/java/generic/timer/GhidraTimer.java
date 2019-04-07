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

public interface GhidraTimer {
	public void start();
	public void stop();
	public void setDelay(int delay);
	public void setInitialDelay(int initialDelay);
	public void setRepeats(boolean repeats);
	public boolean isRepeats();
	public boolean isRunning();
	public int getDelay();
	public int getInitialDelay();
	public void setTimerCallback(TimerCallback callback);
}
