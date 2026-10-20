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
package ghidra.framework.client;

/**
 * {@link AccessRecord} provides the URL Allow List access record used by
 * {@link UrlAllowListManager}.
 * 
 * @param accessAllowed true if access is allowed, false if disallowed
 * @param time date and time when change was made (milliseconds since January 1, 1970, 00:00:00 GMT).
 *                  @see java.lang.System#currentTimeMillis()
 */
public record AccessRecord(boolean accessAllowed, long time) {}
