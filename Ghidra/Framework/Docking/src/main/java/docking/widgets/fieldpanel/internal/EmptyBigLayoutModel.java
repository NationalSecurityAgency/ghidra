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
package docking.widgets.fieldpanel.internal;

import java.awt.Dimension;
import java.math.BigInteger;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.listener.LayoutModelListener;

public class EmptyBigLayoutModel implements LayoutModel {

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
	}

	@Override
	public void flushChanges() {
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		return null;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		return null;
	}

	@Override
	public Layout getLayout(BigInteger index) {
		return null;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(0,0);
	}

	@Override
	public BigInteger getNumIndexes() {
		return BigInteger.ZERO;
	}

	@Override
	public boolean isUniform() {
		return true;
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		// TODO Auto-generated method stub

	}

}
