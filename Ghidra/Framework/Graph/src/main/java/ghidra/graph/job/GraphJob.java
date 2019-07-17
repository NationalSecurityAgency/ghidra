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
package ghidra.graph.job;

/**
 * A graph job is an item of work that needs to be performed.  
 * 
 * @see GraphJobRunner
 */
public interface GraphJob {

	/**
	 * Tells this job to do its work.  This call will be on the Swing thread.  It is required
	 * that the given listener be called on the Swing thread when the job is finished.
	 * 
	 * @param listener the listener this job is expected to call when its work is finished
	 */
	public void execute(GraphJobListener listener);

	/**
	 * Returns true if the job can be told to stop running, but to still perform any final 
	 * work before being done.
	 * 
	 * @return true if the job can be shortcut
	 */
	public boolean canShortcut();

	/**
	 * Tells this job to stop running, but to still perform any final work before being done.
	 * 
	 * <P>Note: if your job is multi-threaded, then you must make sure to end your thread and
	 * work before returning from this method.  If that cannot be done in a timely manner, then
	 * your {@link #canShortcut()} should return false.
	 */
	public void shortcut();

	/**
	 * Returns true if this job has finished its work
	 * @return true if this job has finished its work
	 */
	public boolean isFinished();

	/**
	 * Call to immediately stop this job, ignoring any exceptions or state issues that arise.
	 */
	public void dispose();
}
