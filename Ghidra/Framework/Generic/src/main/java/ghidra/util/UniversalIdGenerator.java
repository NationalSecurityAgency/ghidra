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
package ghidra.util;

import utilities.util.reflection.ReflectionUtilities;

public class UniversalIdGenerator {
	private static UniversalIdGenerator generator;

	public static synchronized UniversalID nextID() {
		if (generator == null) {
			Msg.warn(UniversalIdGenerator.class,
				"nextID called before UniversalIdGenerator initialized!",
				ReflectionUtilities.createJavaFilteredThrowable());

			initialize();
		}
		return generator.getNextID();
	}

	public static synchronized void initialize() {
		if (generator == null) {
			generator = new UniversalIdGenerator();
		}
	}

	static void installGenerator(UniversalIdGenerator newGenerator) {
		UniversalIdGenerator.generator = newGenerator;
	}

	private long baseTime;
	private int instanceCount = Integer.MAX_VALUE;	// set max, so that getNextID will trigger new time
	private int sessionID;
	private long idBase;							// combination of baseTime and uniqueID

	UniversalIdGenerator() {
		this.sessionID = (int) (System.currentTimeMillis() >> 4) & 0xffff;
	}

	protected UniversalID getNextID() {
		if (instanceCount >= 32) {
			baseTime = getNewBaseTime();
			idBase = (baseTime << 21) | (sessionID) << 5;
			instanceCount = 0;
		}
		return new UniversalID(idBase + (instanceCount++));
	}

	private long getNewBaseTime() {
		long newTime = System.currentTimeMillis();
		if (newTime <= baseTime) {
			newTime = baseTime + 1;
		}
		return newTime;
	}

	public static void main(String[] args) {
		UniversalIdGenerator gen = new UniversalIdGenerator();
		UniversalIdGenerator gen2 = new UniversalIdGenerator();
		for (int i = 0; i < 500; i++) {
			System.out.println("id = " + gen.getNextID().getValue() + " next = " +
				Long.toHexString(gen.getNextID().getValue()));
			System.out.println("id2 = " + gen2.getNextID().getValue() + " next = " +
				Long.toHexString(gen2.getNextID().getValue()));
		}
	}
}
