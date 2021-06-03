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
package agent.gdb.manager;

/**
 * A handle/descriptor to a GDB register
 * 
 * This contains a register's name and number
 */
public class GdbRegister implements Comparable<GdbRegister> {
	private final String name;
	private final int number;
	private final int size;

	/**
	 * Construct a new register descriptor
	 * 
	 * @param name the register's name
	 * @param number the GDB-assigned register number
	 * @param the size in bytes
	 */
	public GdbRegister(String name, int number, int size) {
		this.name = name;
		this.number = number;
		this.size = size;
	}

	/**
	 * Get the register's name
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the register's GDB-assigned number
	 * 
	 * @return the number
	 */
	public int getNumber() {
		return number;
	}

	/**
	 * Get the register's size in bytes
	 * 
	 * @return the size
	 */
	public int getSize() {
		return size;
	}

	@Override
	public int compareTo(GdbRegister that) {
		return this.number - that.number;
	}

	@Override
	public String toString() {
		return "<" + getClass().getSimpleName() + " " + name + " (" + number + ")>";
	}
}
