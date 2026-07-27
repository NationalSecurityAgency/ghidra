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
#include <stdio.h>

#include "config.h"
#include "bfd.h"
#include "opcode/tilegx.h"

int main(void)
{
	for (int i = 0; i < TILEGX_OPC_NONE; i++) {
		const struct tilegx_opcode *opcode = &tilegx_opcodes[i];

		for (int pipe = 0; pipe < TILEGX_NUM_PIPELINE_ENCODINGS; pipe++) {
			if ((opcode->pipes & (1u << pipe)) == 0) {
				continue;
			}

			printf("%d\t%s\t%016llx\t%016llx\t%d",
				pipe,
				opcode->name,
				(unsigned long long) opcode->fixed_bit_masks[pipe],
				(unsigned long long) opcode->fixed_bit_values[pipe],
				opcode->num_operands);

			for (int operand = 0; operand < opcode->num_operands; operand++) {
				printf("\t%d", opcode->operands[pipe][operand]);
			}
			putchar('\n');
		}
	}

	return 0;
}
