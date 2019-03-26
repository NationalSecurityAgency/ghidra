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
package generic.algorithms;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.ArrayList;
import java.util.List;

/**
 * Abstract class for finding the LCS between two sequences of Matchable
 * objects.
 * 
 * 
 *
 * @param <T> the type of the objects being compared.
 */
public abstract class LCS<T> {
	private int[][] c;

	/**
	 * Convenient constructor for initializing elements in subclasses 
	 */
	protected LCS() {
	}

	/**
	 * @return the length of the X sequence.
	 */
	protected abstract int lengthOfX();

	/**
	 * @return the length of the Y sequence.
	 */
	protected abstract int lengthOfY();

	/**
	 * @param index the position of interest in the X sequence.
	 * @return the value in the X sequence at <code>index</code>.
	 * Assumes 1-indexing.
	 */
	protected abstract T valueOfX(int index);

	/**
	 * @param index the position of interest in the Y sequence.
	 * @return the value in the Y sequence at <code>index</code>.
	 * Assumes 1-indexing.
	 */
	protected abstract T valueOfY(int index);

	/**
	 * @param x the X-sequence element of interest
	 * @param y the Y-sequence element of interest
	 * @return true if <code>x</code> matches <code>y</code>; false otherwise.
	 */
	protected abstract boolean matches(T x, T y);

	/**
	 * Compute the LCS
	 * @param monitor 
	 */
	private void calculateLCS(TaskMonitor monitor) throws CancelledException {
		if (c != null) {
			return;
		}

		int[][] tempC = new int[lengthOfX() + 1][];

		monitor.setMessage("Calculating LCS...");
		monitor.initialize(tempC.length);

		for (int i = 0; i < tempC.length; i++) {
			// Java int arrays are automatically initialized to 0 
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
	 * @return a <code>List&ltT&gt</code> of elements in the LCS.
	 */
	public List<T> getLCS() {
		try {
			return getLCS(TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// can't happen with a dummy monitor
		}
		return null;
	}

	public List<T> getLCS(TaskMonitor monitor) throws CancelledException {
		calculateLCS(monitor);
		return getLCSHelperIterative(lengthOfX(), lengthOfY());
	}

	/**
	 * Iterative helper function for getLCS().
	 * @param i the current row index
	 * @param j the current column index
	 * @return the LCS after analyzing element c[i, j].
	 */
	private List<T> getLCSHelperIterative(int i, int j) {
		ArrayList<T> result = new ArrayList<T>();
		while (i > 0 && j > 0) {
			if (c[i][j] == c[i - 1][j - 1] + 1 && matches(valueOfX(i), valueOfY(j))) {
				result.add(0, valueOfX(i));
				--i;
				--j;
			}
			else if (c[i][j] == c[i - 1][j]) {
				--i;
			}
			else {
				--j;
			}
		}
		return result;
	}
}
