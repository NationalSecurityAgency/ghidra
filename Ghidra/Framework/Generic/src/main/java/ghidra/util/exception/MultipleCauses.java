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
package ghidra.util.exception;

import java.io.PrintStream;
import java.util.*;

/**
 * Use an instance of this class as the cause when you need to record several causes of an
 * exception.
 * 
 * This paradigm would be necessary when multiple attempts can be made to complete a task, e.g.,
 * traversing a list of plugins until one can handle a given condition. If all attempts fail, it is
 * desirable to report on each attempt.
 * 
 * This class acts as a wrapper allowing multiple causes to be recorded in place of one. The causes
 * recorded in this wrapper actually apply to the throwable ("parent") which has this
 * MultipleCauses exception as its cause. 
 */
public class MultipleCauses extends Throwable {
	// The collection of causes
	private Collection<Throwable> causes = new ArrayList<Throwable>();

	/**
	 * Constructs a new MultipleCauses wrapper with no causes
	 * NOTE: it is rude to leave this empty
	 */
	public MultipleCauses() {
		super("Multiple Causes");
	}

	/**
	 * Constructs a new MultipleCauses wrapper with the given causes
	 * @param causes
	 */
	public MultipleCauses(Collection<Throwable> causes) {
		this();
		this.causes = causes;
	}

	/**
	 * Use getCauses instead
	 * @return null
	 */
	@Override
	public synchronized Throwable getCause() {
		//throw new UnsupportedOperationException("Use getCauses instead");
		return null; // Throwing exception causes "printStackTrace" to fail :(
	}

	/**
	 * Returns the causes of the parent throwable (possibly an empty collection)
	 * @return the collection of causes of the parent throwable
	 * NOTE: it is rude to leave this empty. If the parent throwable has no cause, or the cause is
	 * unknown, leave its cause null. 
	 */
	public synchronized Collection<Throwable> getCauses() {
		return causes;
	}

	/**
	 * Add the cause to the collection of causes (for the "parent" throwable)
	 * @param cause the throwable to add as a cause
	 */
	public synchronized void addCause(Throwable cause) {
		causes.add(cause);
	}

	/**
	 * If the throwable has multiple causes, collect its causes into this MultipleCauses.
	 * Otherwise, just add it as a cause.
	 * @param e
	 */
	public synchronized void addFlattenedIfMultiple(Throwable e) {
		if (hasMultiple(e)) {
			addAllCauses(e);
		}
		else {
			addCause(e);
		}
	}

	/**
	 * Assuming a throwable has multiple causes, add them all to this MultipleCauses
	 * @param e the throwable having multiple causes
	 * 
	 * This is useful for flattening causes into a common exception. For instance, if a method is
	 * collecting multiple causes for a potential WidgetException, and it catches a
	 * WidgetException, instead of collecting the caught WidgetException, it might instead copy
	 * its causes into its own collection.
	 */
	public synchronized void addAllCauses(Throwable e) {
		if (e.getCause() != null) {
			addAllCauses((MultipleCauses) e.getCause());
		}
	}

	/**
	 * Add the causes from another MultipleCauses into this one
	 * @param that the source to copy from
	 */
	public synchronized void addAllCauses(MultipleCauses that) {
		this.causes.addAll(that.causes);
	}

	/**
	 * Use addCause instead
	 */
	public synchronized Throwable initCause(Throwable cause) {
		throw new UnsupportedOperationException("Use addCause instead");
	}

	public synchronized boolean isEmpty() {
		return causes.isEmpty();
	}

	public static boolean hasMultiple(Throwable e) {
		Throwable cause = e.getCause();
		if (cause != null) {
			if (cause instanceof MultipleCauses) {
				return true;
			}
		}
		return false;
	}

	public static void printTree(PrintStream out, Throwable e) {
		printTree(out, "", e);
	}

	// TODO: Look at source of Throwable.printStackTrace and consider overriding it
	public static void printTree(PrintStream out, String prefix, Throwable e) {
		out.print(prefix);
		e.printStackTrace(out);
		if (hasMultiple(e)) {
			if (e.getCause() != null) {
				MultipleCauses report = (MultipleCauses) e.getCause();
				for (Throwable t : report.getCauses()) {
					printTree(out, prefix + ">", t);
				}
			}
		}
	}

	public static class Util {
		public static Iterable<Throwable> iterCauses(Throwable exc) {
			Throwable cause = exc.getCause();
			if (cause instanceof MultipleCauses) {
				return Collections.unmodifiableCollection(((MultipleCauses) cause).getCauses());
			}
			return Collections.singleton(cause);
		}
	}
}
