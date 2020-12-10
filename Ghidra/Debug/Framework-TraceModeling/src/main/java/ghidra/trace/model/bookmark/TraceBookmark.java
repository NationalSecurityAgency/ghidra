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
package ghidra.trace.model.bookmark;

import com.google.common.collect.Range;

import ghidra.program.model.listing.Bookmark;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

public interface TraceBookmark extends Bookmark {
	Trace getTrace();

	/**
	 * If this bookmark is in a register space, identifies the containing thread
	 * 
	 * @return the thread, or null if this bookmark is not in register space
	 */
	TraceThread getThread();

	void setLifespan(Range<Long> lifespan);

	Range<Long> getLifespan();

	@Override
	TraceBookmarkType getType();

	void delete();
}
