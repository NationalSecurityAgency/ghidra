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
package ghidra.app.plugin.core.overview.entropy;

/**
 * Class for storing entropy information for various types found in program such
 */
public class EntropyRecord {
	public String name;
	public double center;
	public double width;

	/**
	 * Constructor
	 *
	 * @param name the name
	 * @param center the center point of the entropy range
	 * @param width the width of the entropy range
	 */
	public EntropyRecord(String name, double center, double width) {
		this.name = name;
		this.center = center;
		this.width = width;
	}

}
