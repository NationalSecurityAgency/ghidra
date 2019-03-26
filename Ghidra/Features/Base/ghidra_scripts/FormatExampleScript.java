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
//<html>An example using the <code><b>printf()</b></code> method of GhidraScript
//@category Examples
import java.util.Calendar;
import java.util.Date;

import ghidra.app.script.GhidraScript;

public class FormatExampleScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(new Date());

		printf("The %s jumped over the %s\n", "cow", "moon");

		printf("The %s jumped over the %s %tT\n", "cow", "moon", Calendar.getInstance());

		printf("The %s jumped over the %s - timestamp: %tc\n", "cow", "moon",
			Calendar.getInstance());

		printf("The %s jumped over the %s at %tl:%<tM on %3$tA, %3$tB %3$te\n", "cow", "moon",
			Calendar.getInstance());

		printf("Padding: %03d\n", 1);

		printf("Hex: 0x%x\n", 10);

		printf("Left-justified: %-10d\n", 1);
		printf("Right-justified: %10d\n", 1);

		printf("String fill: '%10s'\n", "Fill");
		printf("String fill, left justified: '%-10s'\n", "Fill");
	}

}
