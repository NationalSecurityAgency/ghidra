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
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/prctl.h>

int main(int argc, char *argv[], char *envp[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s COMMAND\n\
\n\
    COMMAND A shell command to execute as in /bin/sh -c COMMAND. This must be\n\
            a single argument. To run a command with multiple arguments,\n\
            enclose the full command in quotations.\n\
\n\
Execute the given COMMAND allowing any other process to attach to it. This is\n\
done using prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY), so that on Linux systems\n\
with Yama ptrace_scope=1, gdb, strace, lldb, etc., can attach to it.\n\
", argv[0]);
	}
	char* shell = getpwuid(geteuid())->pw_shell;
	prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
	execl(shell, shell, "-c", argv[1], (char *) NULL);
}
