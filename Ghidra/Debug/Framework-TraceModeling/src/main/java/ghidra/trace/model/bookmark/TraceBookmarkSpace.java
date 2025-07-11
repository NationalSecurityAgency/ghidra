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

import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.util.TraceRegisterUtils;

public interface TraceBookmarkSpace extends TraceBookmarkOperations {
	Trace getTrace();

	AddressSpace getAddressSpace();

	default TraceBookmark addBookmark(Lifespan lifespan, Register register,
			TraceBookmarkType type, String category, String comment) {
		TracePlatform host = getTrace().getPlatformManager().getHostPlatform();
		AddressRange range = host.getConventionalRegisterRange(getAddressSpace(), register);
		return addBookmark(lifespan, range.getMinAddress(), type, category, comment);
	}

	default Iterable<? extends TraceBookmark> getBookmarksEnclosed(Lifespan lifespan,
			Register register) {
		return getBookmarksEnclosed(lifespan, TraceRegisterUtils.rangeForRegister(register));
	}

	default Iterable<? extends TraceBookmark> getBookmarksIntersecting(Lifespan lifespan,
			Register register) {
		return getBookmarksIntersecting(lifespan, TraceRegisterUtils.rangeForRegister(register));
	}
}
