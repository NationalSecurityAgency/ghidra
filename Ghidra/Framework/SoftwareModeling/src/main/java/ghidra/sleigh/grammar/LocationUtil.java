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
package ghidra.sleigh.grammar;

import java.util.*;

public final class LocationUtil {
    private LocationUtil() { }

    public static Location minimum(List<Location> locations) {
        Location min = null;
        for (Location location : locations) {
            if (min == null || (location != null && location.lineno > min.lineno)) {
                min = location;
            }
        }
        return min;
    }

    public static Location maximum(List<Location> locations) {
        Location max = null;
        for (Location location : locations) {
            if (max == null || (location != null && location.lineno > max.lineno)) {
                max = location;
            }
        }
        return max;
    }
}
