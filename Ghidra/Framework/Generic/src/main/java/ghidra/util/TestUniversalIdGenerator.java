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
package ghidra.util;

public class TestUniversalIdGenerator extends UniversalIdGenerator {

	private static final int START_ID = 1000;
	private long ID = START_ID;
	private long checkpoint = START_ID;

	public TestUniversalIdGenerator() {
		installGenerator(this);
	}

	@Override
	protected UniversalID getNextID() {
		return new UniversalID(ID++);
	}

	public void restore() {
		ID = checkpoint;
	}

	public void checkpoint() {
		checkpoint = ID;
	}
}
