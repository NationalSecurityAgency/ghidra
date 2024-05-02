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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Performs appropriated multiple passes on data types to get theme filled in and resolved
 */
public class MultiphaseDataTypeResolver {

	private DefaultPdbApplicator applicator;
	private AbstractPdb pdb;
	private TaskMonitor monitor;

	private RecordStack todoStack;
	private RecordStack resolveStack;

	public MultiphaseDataTypeResolver(DefaultPdbApplicator applicator) {
		this.applicator = applicator;
		this.pdb = applicator.getPdb();
		this.monitor = applicator.getMonitor();
		todoStack = new RecordStack();
		resolveStack = new RecordStack();
	}

	/**
	 * Processes the data type associated with the record number and all dependencies of that
	 *  type.  Deals with cyclic dependencies and ultimately stores resolved (in most cases)
	 *  types in the DefaultPdbApplicator types map
	 * @param recordNumber the record number
	 * @throws PdbException upon processing error
	 * @throws CancelledException upon user cancellation
	 */
	void process(RecordNumber recordNumber) throws PdbException, CancelledException {

		// If found in the applicator map then the type is completed.
		if (applicator.getDataType(recordNumber) != null) {
			return;
		}
		// Location where one might do conditional: todoStack.setDebug(true)

		// If not in the map, it will also not be in the todo or resolve stacks, as both
		//  should be empty at this point.
		scheduleTodo(recordNumber);

		RecordNumber recordToProcess;
		// Peek at top of stack.  If can be removed, it will be; otherwise other records can be
		//  pushed on top of this one for next loop cycle.
		while ((recordToProcess = todoStack.peek()) != null) {
			monitor.checkCancelled();
			MsDataTypeApplier dataTypeApplier =
				(MsDataTypeApplier) applicator.getTypeApplier(recordToProcess);
			AbstractMsType msType = pdb.getTypeRecord(recordToProcess);
			// If processing is done, then pop from todoStack and put onto resolveStack.
			//  If not completed, the do not remove from todoStack.
			if (dataTypeApplier.apply(msType)) {
				if (todoStack.peek() != recordToProcess) {
					throw new AssertException("Top of stack violation");
				}
				todoStack.pop();
				resolveStack.push(recordToProcess);
			}
		}
		// If set true above, location where one might do conditional: todoStack.setDebug(false)

		// Pop top of stack and work on it.
		while ((recordToProcess = resolveStack.pop()) != null) {
			monitor.checkCancelled();
			DataType dataType = applicator.getDataType(recordToProcess);
			// Resolve and re-store most data types
			if (!(dataType instanceof PointerDataType || dataType instanceof BitFieldDataType)) {
				dataType = applicator.resolve(dataType);
				applicator.putDataType(recordToProcess, dataType);
			}
		}
	}

	/**
	 * Method used to schedule another type (indicated by the record number).  This scheduled
	 *  type is put on top of a stack of types to process, pushing what was the current type
	 *  being processed down.  If the type indicated by the record number is already on the stack,
	 *  it is lifted to the top of the stack.  Note that composite types (by virtue of the fact
	 *  that impls for these are created and stored in the applicator map, but not filled in) will
	 *  not be lifted to the top of the stack.  This prevents oscillation on the stack and also
	 *  is the mechanism by which dependency cycles are broken
	 * @param recordNumber the record number to be scheduled
	 */
	void scheduleTodo(RecordNumber recordNumber) {
		MsTypeApplier applier = applicator.getTypeApplier(recordNumber);
		if (!(applier instanceof MsDataTypeApplier dataTypeApplier)) {
			// Return without scheduling... only want to schedule that that have a legitimate
			//  data type to store
			return;
		}
		todoStack.push(recordNumber);
	}

	/**
	 * Stack of record numbers with O(1) push/pop, O(1) contains, O(1) removal from
	 *  anywhere, and thus O(1) move from anywhere to top.  These nodes hold the RecordNumbers
	 *  that are being scheduled
	 */
	static class RecordStack {

		static class RecordNode {
			RecordNode next;
			RecordNode prev;
			RecordNumber recordNumber;

			/**
			 * Create new node for the record number.  Note that the {@code next} and {@code prev}
			 *  values are not set.  They must be set by the RecordStack.
			 * @param recordNumber the record number
			 */
			private RecordNode(RecordNumber recordNumber) {
				this.recordNumber = recordNumber;
			}

			@Override
			public String toString() {
				return recordNumber.toString();
			}
		}

		static final int TO_STRING_LIMIT = 500;
		static final RecordNumber HEAD = RecordNumber.typeRecordNumber(-1);
		static final RecordNumber TAIL = RecordNumber.typeRecordNumber(-2);
		Map<RecordNumber, RecordNode> map;
		RecordNode head;
		RecordNode tail;
		boolean debug;
		StringBuilder debugBuilder;

		/**
		 * Constructor for new record stack
		 */
		RecordStack() {
			// head and tail are not put into the map
			map = new HashMap<>();
			head = new RecordNode(HEAD);
			tail = new RecordNode(TAIL);
			head.next = null;
			head.prev = tail;
			tail.next = head;
			tail.prev = null;
		}

		/**
		 * Set or clear developer debug
		 * @param debug {@code true} to turn on; {@code false} to turn off
		 */
		void setDebug(boolean debug) {
			this.debug = debug;
		}

		/**
		 * Indicates if number number exists on stack
		 * @param recordNumber the record number to check
		 * @return {@code true} if exists
		 */
		boolean contains(RecordNumber recordNumber) {
			return map.containsKey(recordNumber);
		}

		/**
		 * Pushes the record number onto the top of the stack.  If the record number was already
		 *  on the stack, it is moved to the top
		 * @param recordNumber the record number to push
		 */
		void push(RecordNumber recordNumber) {
			RecordNode node = getNode(recordNumber);
			if (node == head.prev) {
				return; // already on top of stack
			}
			if (node == null) {
				node = new RecordNode(recordNumber);
				if (debug) {
					if (map.isEmpty()) {
						debugBuilder = new StringBuilder();
					}
					debugBuilder.append("push:");
					debugBuilder.append(recordNumber);
					debugBuilder.append("\n");
				}
				map.put(recordNumber, node);
			}
			else { // already exists in non-top-of-stack position
				removeNodeLinkage(node);
			}
			insertNodeLinkage(head, node);
		}

		/**
		 * Peek at top node
		 * @return the node's record number or {@code null} if if no nodes left
		 */
		RecordNumber peek() {
			RecordNode node = getTop();
			if (node == tail) {
				return null;
			}
			return node.recordNumber;
		}

		/**
		 * Pop top node
		 * @return the popped node's record number or {@code null} if if no nodes left
		 */
		RecordNumber pop() {
			RecordNode node = getTop();
			if (node == tail) {
				return null;
			}
			removeNodeLinkage(node);
			map.remove(node.recordNumber);
			if (debug) {
				debugBuilder.append(" pop:");
				debugBuilder.append(node.recordNumber);
				debugBuilder.append("\n");
				if (map.isEmpty()) {
					System.out.println(debugBuilder.toString());
				}
			}
			return node.recordNumber;
		}

		/**
		 * Get node for the record number
		 * @return the node
		 */
		private RecordNode getNode(RecordNumber recordNumber) {
			return map.get(recordNumber);
		}

		/**
		 * Get top node
		 * @return the node
		 */
		private RecordNode getTop() {
			return head.prev;
		}

		/**
		 * Add node to the stack.  Gets placed below locationNode, which can be head for pushing
		 * onto the stack
		 */
		private void insertNodeLinkage(RecordNode locationNode, RecordNode newNode) {
			newNode.next = locationNode;
			newNode.prev = locationNode.prev;
			locationNode.prev.next = newNode;
			locationNode.prev = newNode;
		}

		/**
		 * Remove node from bidirectional linkage
		 * @param node the node to remove; must not be {@code head}, {@code tail}, or {@code null}
		 */
		private void removeNodeLinkage(RecordNode node) {
			node.prev.next = node.next;
			node.next.prev = node.prev;
			node.prev = null;
			node.next = null;
		}

		@Override
		public String toString() {
			int count = 0;
			RecordNode node = head.prev;
			StringBuilder builder = new StringBuilder();
			builder.append('[');
			while (node != tail && count < TO_STRING_LIMIT) {
				if (count != 0) {
					builder.append(",");
				}
				builder.append(node);
				node = node.prev;
				count++;
			}
			if (node != tail) {
				builder.append("...");
			}
			builder.append(']');
			return builder.toString();
		}

	}

}
