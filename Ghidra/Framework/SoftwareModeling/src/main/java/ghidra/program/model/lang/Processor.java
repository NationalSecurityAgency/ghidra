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
package ghidra.program.model.lang;

import ghidra.program.util.DefaultLanguageService;

import java.util.HashMap;

public class Processor implements Comparable<Processor> {

	private static HashMap<String, Processor> instances = null;

	private static synchronized void initialize() {
		if (instances == null) {
			instances = new HashMap<String, Processor>();
		}
	}

	/**
	 * Use this method if you want to grab a reference to a Processor given its
	 * name, but if it doesn't exist go ahead and create it anyway and return
	 * the new instance.
	 * 
	 * @param name
	 *            the name of the Processor you're looking for/going to create
	 * @return the Processor
	 */
	public static synchronized Processor findOrPossiblyCreateProcessor(String name) {
		initialize();
		if (!instances.containsKey(name)) {
			register(name);
		}
		return instances.get(name);
	}

	/**
	 * Use this method to look up a Processor from a String when you want a ProcessorNotFoundException
	 * thrown if the Processor isn't found.
	 * <p>
	 * <b><u>Warning:</u></b> Use of this method depends upon languages being loaded.  See
	 * {@link DefaultLanguageService}.
	 * 
	 * @param name
	 *            the name of the Processor you're looking for
	 * @return the Processor
	 * @throws ProcessorNotFoundException if the processor doesn't exist yet
	 */
	public static synchronized Processor toProcessor(String name) {
		initialize();
		Processor processor = instances.get(name);
		if (processor == null) {
			throw new ProcessorNotFoundException(name);
		}
		return processor;
	}

	private final String name;

	private Processor(String name) {
		this.name = name;
	}

	static interface RegisterHook {
		public void register(String name);
	}

	private static RegisterHook registerHook = null;

	private static synchronized Processor register(String name) {
		initialize();
		if (registerHook != null) {
			registerHook.register(name);
		}

		Processor p = new Processor(name);
		instances.put(name, p);
		return p;
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Processor other = (Processor) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		}
		else if (!name.equals(other.name))
			return false;
		return true;
	}

	@Override
	public int compareTo(Processor p) {
		if (p == null) {
			return -1;
		}

		String thisStr = this.toString();
		String otherStr = p.toString();

		return thisStr.compareToIgnoreCase(otherStr);
	}
}
