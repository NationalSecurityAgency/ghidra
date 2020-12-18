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
package ghidra.app.services;

/**
 * A listener for state changes in a recorded target, or in the recorder itself
 * 
 * <P>
 * NOTE: This contains events that would not otherwise be detectable by listening to the destination
 * trace. Some of these can be detected by listening to the model; however, since the recorder is
 * already keeping track of most objects of interest, it makes sense for it to implement some
 * conveniences for accessing and listening to those objects.
 */
public interface TraceRecorderListener {

	/**
	 * A new bank of registers has appeared, and its mapper instantiated
	 * 
	 * @param recorder the recorder
	 */
	default void registerBankMapped(TraceRecorder recorder) {
	}

	/**
	 * Some bank of registers tracked by the given recorder has changed in accessibility
	 * 
	 * @param recorder the recorder
	 */
	default void registerAccessibilityChanged(TraceRecorder recorder) {
	}

	/**
	 * Some portion of process memory tracked by the given recorder has changed in accessibility
	 * 
	 * @param recorder the recorder
	 */
	default void processMemoryAccessibilityChanged(TraceRecorder recorder) {
	}

	/**
	 * The given recorder has ended its recording
	 * 
	 * @param recorder the recorder that stopped
	 */
	default void recordingStopped(TraceRecorder recorder) {
	}

	/**
	 * The recorder has advanced a snap
	 * 
	 * @param recorder the recorder that advanced
	 * @param snap the snap to which it advanced
	 */
	default void snapAdvanced(TraceRecorder recorder, long snap) {
	}
}
