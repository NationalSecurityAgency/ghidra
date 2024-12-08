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
package ghidra.bsfv;

/**
 * This class is used to display the actual BSim feature in the BSim feature table.  Formally, 
 * a BSim feature is a 32 bit hash.  We wrap such an integer with an instance of this class in 
 * order to force a particular unsigned comparison and hexadecimal display in the feature table.
 */
public class BsfvFeatureColumnObject implements Comparable<BsfvFeatureColumnObject> {

	private int bsimFeature;

	/**
	 * Creates a BSimFeatureColumnType corresponding to the BSim feature with the given hash
	 * @param hash feature value
	 */
	public BsfvFeatureColumnObject(int hash) {
		bsimFeature = hash;
	}

	@Override
	public String toString() {
		return Integer.toHexString(bsimFeature);
	}

	@Override
	public int compareTo(BsfvFeatureColumnObject o) {
		return Integer.compareUnsigned(bsimFeature, o.bsimFeature);
	}

}
