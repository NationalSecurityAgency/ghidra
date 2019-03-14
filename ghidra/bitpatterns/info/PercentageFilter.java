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
package ghidra.bitpatterns.info;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeFilter;

/**
 * 
 * Objects in this class are used to filter instruction tree nodes by percentage.
 *
 */

public class PercentageFilter implements GTreeFilter {

	private double percentage;

	/**
	 *
	 * @param percentage - must be between 0.0 and 100.0, inclusive
	 */
	public PercentageFilter(double percentage) {
		if (percentage < 0.0 || percentage > 100.0) {
			throw new IllegalArgumentException("Not a valid percentage: " + percentage);
		}
		this.percentage = percentage;
	}

	/**
	 * 
	 * @param percentageToTest
	 * @return true precisely when percentageToTest >= percentage
	 */
	public boolean allows(double percentageToTest) {
		return percentageToTest >= percentage;
	}

	@Override
	public String toString() {
		return "Percentage: " + Double.toString(percentage);
	}

	@Override
	public boolean acceptsNode(GTreeNode node) {
		if (!(node instanceof FunctionBitPatternsGTreeNode)) {
			return false;
		}
		FunctionBitPatternsGTreeNode fbpgNode = (FunctionBitPatternsGTreeNode) node;
		return fbpgNode.getPercentage() >= percentage;
	}

	@Override
	public boolean showFilterMatches() {
		return true;
	}

}
