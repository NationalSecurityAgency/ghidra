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
package ghidra.framework.model;

import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * <code>DomainObjectException</code> provides a general RuntimeException 
 * when a catastrophic error occurs which may affect the integrity of a 
 * domain object such as an IOException.
 */
public class DomainObjectException extends RuntimeException {

	Throwable t;

	/**
	 * Constructor.
	 * @param t throwable error/exception which provides failure detail.
	 */
	public DomainObjectException(Throwable t) {
		super(t);
		this.t = t;
	}

	/*
	 * @see java.lang.Throwable#printStackTrace()
	 */
	@Override
	public void printStackTrace() {
		if (t != null) {
			t.printStackTrace();
		}
		else {
			super.printStackTrace();
		}
	}

	/*
	 * @see java.lang.Throwable#printStackTrace(java.io.PrintStream)
	 */
	@Override
	public void printStackTrace(PrintStream s) {
		if (t != null) {
			t.printStackTrace(s);
		}
		else {
			super.printStackTrace(s);
		}
	}

	/*
	 * @see java.lang.Throwable#printStackTrace(java.io.PrintWriter)
	 */
	@Override
	public void printStackTrace(PrintWriter s) {
		if (t != null) {
			t.printStackTrace(s);
		}
		else {
			super.printStackTrace(s);
		}
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (t != null) {
			return getClass().getName() + " caused by: " + t.toString();
		}
		return super.toString();
	}

}
