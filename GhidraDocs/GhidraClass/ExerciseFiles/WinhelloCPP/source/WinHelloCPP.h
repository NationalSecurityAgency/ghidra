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
#pragma once

#include "resource.h"

enum StateMask { READ = 1, WRITE = 2, EXEC = 4, LOCKED = 8 };

typedef struct _person {
	int  id;
	char name[32];
	bool likesCheese;
	struct _person *next;
} Person;

void addPeople(Person **list);

void initializePeople(Person *people);

void addPerson (Person **list, char *name);

void doPaint(HDC hDC, RECT rect);
