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
package generic.concurrent;

import java.util.concurrent.CancellationException;
import java.util.concurrent.Future;

/**
 * Class for holding the result of processing an Item in a ConcurrentQ.
 * 
 * @param <I> the type of the items in the ConcurrentQ.
 * @param <R> the type of objects returned from processing an item in a ConcurrentQ.
 */

public class QResult<I, R> {
	private final I item;
	private final R result;
	private final Exception error;

	public QResult(I item, Future<R> future) {
		this.item = item;
		R tempResult;
		Exception tempError;

		try {
			tempResult = future.get();
			tempError = null;
		}
		catch (Exception e) {
			tempError = e;
			tempResult = null;
		}
		result = tempResult;
		error = tempError;
	}

	/**
	 * Returns the item that was processed.
	 * @return the item that was processed.
	 */
	public I getItem() {
		return item;
	}

	/**
	 * The result from processing the item.  Will be null if the item was cancelled or had an error.
	 * 
	 * @return the result from processing the item or null if it did not complete successfully.
	 * @throws Exception any exception that was thrown during the processing of the input item
	 */
	public R getResult() throws Exception {
		if (hasError()) {
			throw error;
		}
		return result;
	}

	/**
	 * Returns any Exception that was encountered during processing of the item
	 * @return any Exception that was encountered during processing of the item
	 */
	public Exception getError() {
		return hasError() ? error : null;
	}

	/**
	 * Returns true if the item encountered an error while processing the item.
	 * @return true if the item encountered an error while processing the item.
	 */
	public boolean hasError() {
		return error != null && !(error instanceof CancellationException);
	}

	/**
	 * Returns true if the item's processing was cancelled.
	 * @return true if the item's processing was cancelled.
	 */
	public boolean isCancelled() {
		return error instanceof CancellationException;
	}
}
