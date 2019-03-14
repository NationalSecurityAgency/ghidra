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
package ghidra.app.util.bin.format.pe.rich;

public class CompId {
	private final int id;
	private final int productId;
	private final int buildNumber;

	public CompId(int id) {
		this.id = id;
		this.productId = id >> 16;
		this.buildNumber = id & 0x0000FFFF;
	}

	public int getValue() {
		return id;
	}

	public int getProductId() {
		return productId;
	}

	public String getProductDescription() {

		RichProduct prod = RichHeaderUtils.getProduct(getProductId());

		StringBuilder sb = new StringBuilder();

		String prodVersion =
			prod == null ? "Unknown Product (" + Integer.toHexString(getProductId()) + ")"
					: prod.getProductVersion();
		MSProductType prodType = prod == null ? MSProductType.Unknown : prod.getProductType();

		if (prodType != MSProductType.Unknown) {
			sb.append(prodType).append(" from ").append(prodVersion);
		}
		else {
			sb.append(prodVersion);
		}

		return sb.toString();

	}

	public int getBuildNumber() {
		return buildNumber;
	}

	@Override
	public String toString() {
		return getProductDescription() + ", build " + getBuildNumber();
	}

}
