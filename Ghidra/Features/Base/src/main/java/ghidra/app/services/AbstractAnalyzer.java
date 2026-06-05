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
package ghidra.app.services;

import java.util.Set;

import generic.concurrent.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractAnalyzer implements Analyzer {
	private final String name;
	private final AnalyzerType type;
	private final String description;
	private boolean defaultEnablement = false;
	private boolean supportsOneTimeAnalysis;
	private boolean isPrototype = false;
	private AnalysisPriority priority = AnalysisPriority.LOW_PRIORITY;
	
	protected static final AddressSetView EMPTY_ADDRESS_SET = new AddressSetViewAdapter();

	protected AbstractAnalyzer(String name, String description, AnalyzerType type) {
		this.name = name;
		this.type = type;
		this.description = description;
	}

	protected void setPriority(AnalysisPriority priority) {
		this.priority = priority;
	}

	protected void setDefaultEnablement(boolean b) {
		this.defaultEnablement = b;
	}

	protected void setSupportsOneTimeAnalysis() {
		supportsOneTimeAnalysis = true;
	}

	protected void setSupportsOneTimeAnalysis(boolean supportsOneTimeAnalysis) {
		this.supportsOneTimeAnalysis = supportsOneTimeAnalysis;
	}

	protected void setPrototype() {
		isPrototype = true;
	}

	@Override
	public final String getName() {
		return name;
	}

	@Override
	public final AnalyzerType getAnalysisType() {
		return type;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return defaultEnablement;
	}

	@Override
	public final boolean supportsOneTimeAnalysis() {
		return supportsOneTimeAnalysis;
	}

	@Override
	public final String getDescription() {
		return description == null ? "No Description" : description;
	}

	@Override
	public final AnalysisPriority getPriority() {
		return priority;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		// do nothing
	}

	@Override
	public void analysisEnded(Program program) {
		// do nothing
	}

	@Override
	public final boolean isPrototype() {
		return isPrototype;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// do nothing
	}
	
	/**
	 * Analyze a single location
	 * 
	 * @param program - program to analyze
	 * @param start - location to start flowing constants
	 * @param set - restriction set of addresses to analyze
	 * @param monitor - monitor to check canceled
	 * 
	 * @return - set of addresses actually flowed to
	 * @throws CancelledException
	 */
	public AddressSetView analyzeLocation(final Program program, Address start, AddressSetView set,
			final TaskMonitor monitor) throws CancelledException {
		return EMPTY_ADDRESS_SET;
	}

	/**
	 * Run constant an analysis at each location in parallel
	 * 
	 * @param program program
	 * @param locations points to analyze
	 * @param restrictedSet set to restrict analysis to, null if none
	 * @param maxThreads maximum number of threads to use
	 * @param monitor to cancel
	 * @return set of addresses covered during analysis
	 * 
	 * @throws CancelledException if cancelled
	 * @throws InterruptedException if interrupted
	 * @throws Exception any exception
	 */
	protected AddressSetView runParallelAddressAnalysis(final Program program, final Set<Address> locations, final AddressSetView restrictedSet, int maxThreads,
			final TaskMonitor monitor) throws CancelledException, InterruptedException, Exception {
			
				monitor.checkCancelled();
			
				final AddressSet analyzedSet = new AddressSet();
				if (locations.isEmpty()) {
					return analyzedSet;
				}
			
				GThreadPool pool = AutoAnalysisManager.getSharedAnalsysThreadPool();
				monitor.setMaximum(locations.size());
			
				QCallback<Address, AddressSetView> callback = new QCallback<Address, AddressSetView>() {
					@Override
					public AddressSetView process(Address loc, TaskMonitor taskMonitor) {
						synchronized (analyzedSet) {
							if (analyzedSet.contains(loc)) {
								taskMonitor.incrementProgress(1);
								return EMPTY_ADDRESS_SET;
							}
						}
			
						try {
							AddressSetView result = analyzeLocation(program, loc, restrictedSet, taskMonitor);
							synchronized (analyzedSet) {
								analyzedSet.add(result);
							}
			
							taskMonitor.incrementProgress(1);
							return result;
						}
						catch (CancelledException e) {
							return null; // monitor was cancelled
						}
					}
				};
				
				// bound check thread limit	
				if (maxThreads > pool.getMaxThreadCount()) {
					maxThreads = pool.getMaxThreadCount();
				}
				if (maxThreads < 1) {
					maxThreads = 1;
				}
				
				// @formatter:off
				ConcurrentQ<Address, AddressSetView> queue = new ConcurrentQBuilder<Address, AddressSetView>()
					.setThreadPool(pool)
					.setMaxInProgress(maxThreads)
					.setMonitor(monitor)
					.build(callback);
				// @formatter:on
			
				queue.add(locations);
			
				queue.waitUntilDone();
			
				return analyzedSet;
			}

}
