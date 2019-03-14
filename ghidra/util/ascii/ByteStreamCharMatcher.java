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
package ghidra.util.ascii;

/**
 * ByteStreamCharMatcher are state machines used to look for char sequences within a stream of bytes.  
 * Bytes from the stream are added one a time and converted to character stream which are in
 * turn fed into a char stream recognizer.  As each byte is added, an indication is returned if that byte caused
 * a terminated sequence to be found.  A sequence is simply a pair of indexes indicated the start and
 * end indexes into the byte stream where the char sequence started and ended respectively along with
 * an indication that the sequence was null terminated.
 *
 */
public interface ByteStreamCharMatcher {

	/**
	 * Adds the next contiguous byte to this matcher 
	 * @param b the next contiguous byte in the search stream.
	 * @return true if the given byte triggered a sequence match.  Note that this byte may not be
	 * a part of the recognized sequence. 
	 */
	public boolean add(byte b);

	/**
	 * Tells the matcher that there are no more contiguous bytes.  If the current state of the 
	 * matcher is such that there is a valid sequence that can be at the end of the stream, then
	 * a sequence will be created and true will be returned.
	 * 
	 * @return true if there is a valid sequence at the end of the stream. 
	 */
	public boolean endSequence();

	/**
	 * Returns the currently recognized sequence which only exists immediately after an add or
	 * end sequence is called with a return value of true.
	 * @return
	 */
	public Sequence getSequence();

	/**
	 * Resets the internal state of this ByteMatcher so that it can be reused against another byte stream.
	 */
	public void reset();
}
