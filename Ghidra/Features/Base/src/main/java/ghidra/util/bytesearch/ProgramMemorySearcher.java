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
package ghidra.util.bytesearch;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for efficiently searching for one or more patterns in memory. Patterns used by this 
 * class can be any class that implements {@link BytePattern}, so clients are free to create
 * their own custom pattern classes.
 * <P>
 * Note: this searcher searches each memory block individually. It intentionally does not find
 * patterns that span memory blocks (even if the memory blocks are adjacent). If you want patterns
 * to span memory blocks, you can use the {@link MemorySearcher} class, which is not block
 * oriented.
 *
 * @param <T> The specific pattern class type
 */
public class ProgramMemorySearcher<T extends BytePattern> {
	private static final int BUF_SIZE = 4096;
	private BulkPatternSearcher<T> patternSearcher;
	private Program program;
	private String name;
	private int maxPatternLength;

	private AddressableByteSequence pre;
	private AddressableByteSequence main;
	private AddressableByteSequence post;
	private List<Match<T>> intermediateResults = new ArrayList<>();

	/**
	 * Constructor
	 * @param name the name of the searcher. (Used by the task monitor messages)
	 * @param program The program whose memory is to be searched
	 * @param patterns the list of pattern objects to search for
	 */
	public ProgramMemorySearcher(String name, Program program, List<T> patterns) {
		this(name, program, new BulkPatternSearcher<T>(patterns));
	}

	/**
	 * Constructor
	 * @param name the name of the searcher. (Used by the task monitor messages)
	 * @param program The program whose memory is to be searched
	 * @param patternSearcher the pre-constructed pattern searcher which is state-less and be
	 * reused, saving the time of building the state machine for the patterns.
	 */
	public ProgramMemorySearcher(String name, Program program,
			BulkPatternSearcher<T> patternSearcher) {
		this.name = name;
		this.program = program;
		this.patternSearcher = patternSearcher;
		this.maxPatternLength = patternSearcher.getMaxPatternLength();
		ProgramByteSource programByteSource = new ProgramByteSource(program);
		pre = new AddressableByteSequence(programByteSource, BUF_SIZE);
		main = new AddressableByteSequence(programByteSource, BUF_SIZE);
		post = new AddressableByteSequence(programByteSource, BUF_SIZE);
	}

	/**
	 * Searches all initialized memory in the program for the patterns given to this searcher.
	 * @param consumer the consumer to be called back when a match is found
	 * @param monitor the task monitor for reporting progress and allowing for cancellation
	 * @throws CancelledException thrown if the search is cancelled via the task monitor
	 */
	public void searchAll(Consumer<AddressMatch<T>> consumer, TaskMonitor monitor)
			throws CancelledException {
		search(program.getMemory().getLoadedAndInitializedAddressSet(), consumer, monitor);
	}

	/**
	 * Searches the given address set within initialized memory for the patterns given to this
	 * searcher.
	 * @param addresses The address within the program to search. This address set will be further
	 * restricted to initialized program memory
	 * @param consumer the consumer to be called back when a match is found
	 * @param monitor the task monitor for reporting progress and allowing for cancellation
	 * @throws CancelledException thrown if the search is cancelled via the task monitor
	 */
	public void search(AddressSetView addresses, Consumer<AddressMatch<T>> consumer,
			TaskMonitor monitor) throws CancelledException {

		Memory memory = program.getMemory();

		// we can't search in uninitialized memory, so exclude those addresses
		AddressSet initializedAddresses = addresses.intersect(memory.getAllInitializedAddressSet());
		monitor.setMessage(name);
		monitor.initialize(initializedAddresses.getNumAddresses());

		MemoryBlock[] blocks = memory.getBlocks();
		for (MemoryBlock memoryBlock : blocks) {
			monitor.checkCancelled();
			searchBlock(memoryBlock, initializedAddresses, consumer, monitor);
		}
	}

	private void searchBlock(MemoryBlock block, AddressSet addresses,
			Consumer<AddressMatch<T>> consumer, TaskMonitor monitor) throws CancelledException {

		AddressSet blockSet = addresses.intersectRange(block.getStart(), block.getEnd());
		for (AddressRange range : blockSet) {
			searchRange(block, range, consumer, monitor);
		}
	}

	private void searchRange(MemoryBlock block, AddressRange range,
			Consumer<AddressMatch<T>> consumer, TaskMonitor monitor) throws CancelledException {
		pre.clear();
		main.clear();
		post.clear();

		// load data before range to allow for pre sequence patterns to match
		populatePreSequenceForLookBehindPatterns(block, range);

		AddressRangeSplitter splitter = new AddressRangeSplitter(range, BUF_SIZE, true);
		main.setRange(splitter.next());
		while (splitter.hasNext()) {
			monitor.checkCancelled();
			post.setRange(splitter.next());
			performSearch(consumer);
			monitor.incrementProgress(range.getLength());
			rotateBuffers();
		}
		// load data some past end of range to allow pattern to complete
		populatePostSequenceForPatternCompletion(block, range);
		performSearch(consumer);
	}

	private void performSearch(Consumer<AddressMatch<T>> consumer) {
		intermediateResults.clear();
		int overlapSize = maxPatternLength; // number of bytes in pre/post that need to be used
		ExtendedByteSequence sequence = new ExtendedByteSequence(main, pre, post, overlapSize);
		patternSearcher.search(sequence, intermediateResults);
		for (Match<T> match : intermediateResults) {
			long start = match.getStart() + match.getPattern().getPreSequenceLength();
			Address address = main.getAddress((int) start);
			int length = match.getLength();
			T pattern = match.getPattern();
			AddressMatch<T> addressMatch = new AddressMatch<>(pattern, start, length, address);
			consumer.accept(addressMatch);
		}
	}

	private void rotateBuffers() {
		AddressableByteSequence tmp = pre;
		pre = main;
		main = post;
		post = tmp;
	}

	private void populatePreSequenceForLookBehindPatterns(MemoryBlock block, AddressRange range) {
		Address blockStart = block.getStart();
		Address rangeStart = range.getMinAddress();
		if (rangeStart.equals(blockStart)) {
			return;
		}
		// We don't go back beyond block start for pre bytes
		int availablePreBytes = (int) rangeStart.subtract(blockStart);
		int preSize = Math.min(availablePreBytes, maxPatternLength);
		Address preStartAddress = rangeStart.subtract(preSize);
		pre.setRange(preStartAddress, preSize);
	}

	private void populatePostSequenceForPatternCompletion(MemoryBlock block, AddressRange range) {
		Address blockEnd = block.getEnd();
		Address rangeEnd = range.getMaxAddress();
		if (rangeEnd.equals(blockEnd)) {
			return;
		}
		int availablePostBytes = (int) blockEnd.subtract(rangeEnd);
		int postSize = Math.min(availablePostBytes, maxPatternLength);
		post.setRange(rangeEnd.next(), postSize);
	}
}
