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

public class RichProduct {
	private final CompId compid;
	private final String productVersion;
	private final MSProductType productType;

	public RichProduct(int compid, String version, MSProductType type) {
		this.compid = new CompId(compid);
		this.productVersion = version;
		this.productType = type;
	}

	public CompId getCompid() {
		return compid;
	}

	public String getProductVersion() {
		return productVersion;
	}

	public MSProductType getProductType() {
		return productType;
	}

	@Override
	public String toString() {
		return getProductVersion() + " -- " + getProductType();
	}

}
