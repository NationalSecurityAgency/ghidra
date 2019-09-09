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
package docking.widgets.fieldpanel.listener;

import java.math.BigInteger;

public interface LayoutModelListener {

	/**
	 * Called whenever the number of indexes changed
	 * @param indexMapper Maps indexes from before the model size change to indexes after
	 * the model size changed.
	 */
	void modelSizeChanged(IndexMapper indexMapper);

	/**
	 * Called when the data at an index or range of indexes changes.
	 * @param start the starting index for the region of data changes.
	 * @param end the ending index (inclusive) for the region of data changes.
	 *
	 */
	void dataChanged(BigInteger start, BigInteger end);

}
