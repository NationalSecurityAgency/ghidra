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
package generic.algorithms;

import java.util.ArrayList;
import java.util.List;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Abstract class for finding the Longest Common Subsequence (LCS) between two 
 * sequences of Matchable objects, <code>x</code> and <code>y</code>.
 * 
 * <p>The performance of this algorithm is O(n^2).  Thus, large inputs can cause much processor
 * and memory usage.   This class has an upper limit (see {@link #getSizeLimit()}) to prevent
 * accidental system failure.   
 *
 * @param <T> the type of the objects being compared
 */
public abstract class Lcs<T> {

	/**
	 * Somewhat arbitrary upper-bound restriction.  1M is 1000 * 1000
	 */
	private static int DEFAULT_SIZE_LIMIT = 1_000_000;
	private int sizeLimit = DEFAULT_SIZE_LIMIT;

	private int[][] c;

	/**
	 * Returns the length of the x sequence
	 * @return the length of the x sequence
	 */
	protected abstract int lengthOfX();

	/**
	 * Returns the length of the y sequence
	 * @return the length of the y sequence
	 */
	protected abstract int lengthOfY();

	/**
	 * Gets the value of the x sequence at the given index, where index is 1-based
	 * 
	 * @param index the 1-based position of interest in the x sequence
	 * @return the value in the x sequence at <code>index</code>
	 */
	protected abstract T valueOfX(int index);

	/**
	 * Gets the value of the y sequence at the given index, where index is 1-based
	 * 
	 * @param index the 1-based position of interest in the Y sequence
	 * @return the value in the y sequence at <code>index</code>
	 */
	protected abstract T valueOfY(int index);

	/**
	 * Returns true if the value of x and y match
	 * 
	 * @param x the x-sequence element of interest
	 * @param y the y-sequence element of interest
	 * @return true if <code>x</code> matches <code>y</code>; false otherwise
	 */
	protected abstract boolean matches(T x, T y);

	/**
	 * Compute the LCS
	 * @param monitor the task monitor
	 */
	private void calculateLCS(TaskMonitor monitor) throws CancelledException {
		if (c != null) {
			return;
		}

		if (tooBig()) {
			c = new int[0][0];
			return;
		}

		int[][] tempC = new int[lengthOfX() + 1][];

		monitor.setMessage("Calculating LCS...");
		monitor.initialize(tempC.length);

		// create the zero-initialized matrix
		for (int i = 0; i < tempC.length; i++) {
			tempC[i] = new int[lengthOfY() + 1];
		}

		for (int i = 1; i < tempC.length; i++) {
			monitor.checkCanceled();
			for (int j = 1; j < tempC[i].length; j++) {
				if (matches(valueOfX(i), valueOfY(j))) {
					tempC[i][j] = tempC[i - 1][j - 1] + 1;
				}
				else {
					tempC[i][j] = Math.max(tempC[i][j - 1], tempC[i - 1][j]);
				}
			}
			monitor.incrementProgress(1);
		}

		c = tempC;
	}

	/**
	 * Defines an limit in the overall size of the inputs that above which no processing will
	 * take place.  Any value over the limit will produce an empty LCS.
	 * 
	 * @return true if too big
	 */
	private boolean tooBig() {
		return lengthOfX() * lengthOfY() > sizeLimit;
	}

	/**
	 * Changes the size limit of this LCS, past which no calculations will be performed
	 * 
	 * @param newLimit the new limit
	 */
	public void setSizeLimit(int newLimit) {
		this.sizeLimit = newLimit;
	}

	/**
	 * Returns the current size limit, past which no calculations will be performed
	 * 
	 * @return the size limit
	 * @see #setSizeLimit(int)
	 */
	public int getSizeLimit() {
		return sizeLimit;
	}

	/**
	 * Returns a list of the longest common subsequence.  This result will be empty if the 
	 * {@link #getSizeLimit()} has been reached.
	 * 
	 * @return the list
	 */
	public List<T> getLcs() {
		try {
			return getLcs(TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen with a dummy monitor
		}
		return null;
	}

	/**
	 * Returns a list of the longest common subsequence. This result will be empty if the 
	 * {@link #getSizeLimit()} has been reached.
	 * 
	 * @param monitor the task monitor
	 * @return the LCS list
	 * @throws CancelledException if the monitor is cancelled
	 */
	public List<T> getLcs(TaskMonitor monitor) throws CancelledException {
		calculateLCS(monitor);
		return doGetLcs(monitor);
	}

	/**
	 * Get the actual LCS based upon the already created matrix
	 * 
	 * @param monitor the task monitor
	 * @return the LCS list
	 * @throws CancelledException if the monitor is cancelled
	 */
	protected List<T> doGetLcs(TaskMonitor monitor) throws CancelledException {

		int x = 0;
		int y = 0;

		if (c.length > 0) {
			x = lengthOfX();
			y = lengthOfY();
		}

		List<T> result = new ArrayList<>();
		while (x > 0 && y > 0) {
			monitor.checkCanceled();

			if (c[x][y] == c[x - 1][y - 1] + 1 && matches(valueOfX(x), valueOfY(y))) {
				result.add(0, valueOfX(x));
				--x;
				--y;
			}
			else if (c[x][y] == c[x - 1][y]) {
				--x;
			}
			else {
				--y;
			}
		}
		return result;
	}
}
