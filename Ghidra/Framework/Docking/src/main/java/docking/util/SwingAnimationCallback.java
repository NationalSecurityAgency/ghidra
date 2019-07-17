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
package docking.util;

/**
 * A simple interface that allows implementing clients to get called back from the animation
 * framework.  The callbacks can be used to perform swing work.
 */
public interface SwingAnimationCallback {

	/**
	 * Called over the course of an animation cycle.  
	 * 
	 * @param percentComplete a value (from 0 to 1.0) that indicates the percentage of the 
	 *                        animation cycle that has completed.
	 */
	public void progress(double percentComplete);

	/**
	 * Called when the entire animation cycle is done.  This allows clients to perform any
	 * finalization work.
	 */
	public void done();

	/**
	 * Returns the duration of this callback.  The default is <code>1000 ms</code>.  Subclasses
	 * can override this as needed.
	 * 
	 * @return the duration
	 */
	public default int getDuration() {
		return 1000;
	}
}
