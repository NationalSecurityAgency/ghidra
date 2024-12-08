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
package ghidra.trace.model.symbol;

import java.util.Collection;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

/**
 * A trace symbol.
 *
 * <p>
 * This is essentially the equivalent concept of {@link Symbol} from a {@link Program}. One
 * important distinction is that in the trace implementation, the symbol and the object it describes
 * are the same. For example, in a {@link Program}, a {@link Namespace} and its symbol are two
 * different things. To get the namespace, you would invoke {@link Symbol#getObject()}. That is
 * unnecessary, though permissible, with a trace, because {@link TraceNamespaceSymbol} extends from
 * both {@link Namespace} and {@link Symbol}.
 */
public interface TraceSymbol extends Symbol {
	/**
	 * Get the trace to which this symbol belongs.
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * If in register space, get the thread associated with this symbol.
	 * 
	 * @return the thread
	 */
	TraceThread getThread();

	@Override
	TraceNamespaceSymbol getParentNamespace();

	@Override
	TraceNamespaceSymbol getParentSymbol();

	/**
	 * {@inheritDoc}
	 * 
	 * For traces, {@link #getReferenceCollection()} is preferred, as it will retrieve the
	 * references lazily.
	 */
	@Override
	TraceReference[] getReferences(TaskMonitor monitor);

	/**
	 * Get all memory references to the address of this symbol.
	 * 
	 * @return the references
	 */
	Collection<? extends TraceReference> getReferenceCollection();

	/**
	 * {@inheritDoc}
	 * 
	 * For traces, {@link #getReferenceCollection()} is preferred, as it will retrieve the
	 * references lazily.
	 */
	@Override
	TraceReference[] getReferences();

	/**
	 * {@inheritDoc}
	 * 
	 * Traces do not support moving memory, so pinning is meaningless and unsupported.
	 */
	@Override
	void setPinned(boolean pinned);

	/**
	 * {@inheritDoc}
	 * 
	 * Traces do not support moving memory, so pinning is meaningless and unsupported.
	 */
	@Override
	boolean isPinned();
}
