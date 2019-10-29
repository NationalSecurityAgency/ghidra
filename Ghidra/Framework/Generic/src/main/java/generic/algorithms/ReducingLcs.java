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
 * Calculates the longest common subsequence (LCS) between two sequences of Matchable 
 * objects, <code>x</code> and <code>y</code>.
 * 
 * <p>This is an optimizing version of the {@link Lcs} that will pre-calculate all similar 
 * items from the beginning and end of the two given sequences.  Doing this will reduce 
 * the size of the matrix created by the parent class, greatly so in the case that the 
 * two inputs are mostly the same in the beginning and end.  (Imagine an edit of a source 
 * code file, where the typical change is somewhere in the middle of the file.  In this example, 
 * the optimization performed here can greatly decrease the amount of work to be performed when 
 * calculating the LCS.)
 * 
 * <p>Note: the parent LCS algorithm is bound by {@link #getSizeLimit()}.  However, this class 
 * allows clients to work around this restriction when the data has a similar beginning and ending, 
 * as the similar parts will not be counted against the size limit.
 *
 * @param <I> The input sequence type
 * @param <T> the individual element type of the input sequence
 */
public abstract class ReducingLcs<I, T> extends Lcs<T> {

	private I xSource; // full input x
	private I ySource; // full input y

	private I x; // the reduced input x 
	private I y; // the reduced input y

	private int startn; // number of beginning same entries 
	private int endn;   // number of trailing same entries

	/**
	 * Constructor
	 * 
	 * @param ix the input sequence <code>x</code>
	 * @param iy the input sequence <code>y</code>
	 */
	public ReducingLcs(I ix, I iy) {
		this.xSource = ix;
		this.ySource = iy;

		startn = getMatchCountFromStart();
		endn = getMatchCountFromEnd();
		int endx = getEnd(xSource);
		int endy = getEnd(ySource);
		this.x = reduce(ix, startn, endx);
		this.y = reduce(iy, startn, endy);
	}

	private int getEnd(I i) {
		int end = lengthOf(i) - endn;
		if (end <= startn) {
			// boundary condition when the change is only a delete or insert 
			end = startn;
		}
		return end;
	}

	/**
	 * Create a subsequence from the given input sequence.  
	 *  
	 * @param i the input sequence; 0-based (x or y)
	 * @param start the start index; 0-based (inclusive)
	 * @param end the end index (exclusive)
	 * @return the subsequence
	 */
	protected abstract I reduce(I i, int start, int end);

	/**
	 * Return the length of the given sequence
	 * 
	 * @param i the input sequence (x or y)
	 * @return the length
	 */
	protected abstract int lengthOf(I i);

	/**
	 * Return the value at the given 0-based offset
	 *  
	 * @param i the input sequence (x or y)
	 * @param offset the offset
	 * @return the value
	 */
	protected abstract T valueOf(I i, int offset);

	@Override
	protected List<T> doGetLcs(TaskMonitor monitor) throws CancelledException {

		List<T> reducedLcs = super.doGetLcs(monitor);
		int size = reducedLcs.size() + lengthOf(x) + lengthOf(y);
		List<T> lcs = new ArrayList<>(size);

		// add the shared beginning
		for (int i = 0; i < startn; i++) {
			monitor.checkCanceled();
			lcs.add(valueOf(xSource, i));
		}

		// add the calculated LCS
		lcs.addAll(reducedLcs);

		// add the shared end
		int length = lengthOf(xSource);
		int endx = getEnd(xSource);
		for (int i = endx; i < length; i++) {
			monitor.checkCanceled();
			lcs.add(valueOf(xSource, i));
		}

		return lcs;
	}

	@Override
	protected int lengthOfX() {
		return lengthOf(x);
	}

	@Override
	protected int lengthOfY() {
		return lengthOf(y);
	}

	@Override
	protected T valueOfX(int index) {
		return valueOf(x, index - 1);
	}

	@Override
	protected T valueOfY(int index) {
		return valueOf(y, index - 1);
	}

	@Override
	protected boolean matches(T tx, T ty) {
		return tx.equals(ty);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private int getMatchCountFromStart() {

		// scan past the beginning of all equal items
		int n = 0;
		int xl = lengthOf(xSource);
		int yl = lengthOf(ySource);
		while (n < xl && n < yl) {
			T xt = valueOf(xSource, n);
			T yt = valueOf(ySource, n);
			if (!matches(xt, yt)) {
				return n;
			}
			n++;
		}

		return 0;
	}

	private int getMatchCountFromEnd() {

		// scan past the trailing equal items
		int xi = lengthOf(xSource) - 1;
		int yi = lengthOf(ySource) - 1;

		int n = 0;
		for (; xi >= 0 && yi >= 0; xi--, yi--) {
			T xt = valueOf(xSource, xi);
			T yt = valueOf(ySource, yi);
			if (!matches(xt, yt)) {
				return n == 0 ? 0 : n - 1;
			}
			n++;
		}

		return 0;
	}

}
