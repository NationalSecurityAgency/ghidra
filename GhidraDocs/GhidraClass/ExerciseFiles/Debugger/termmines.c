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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <ncurses.h>

#define MIN_WIDTH 10
#define MAX_WIDTH 30

#define MIN_HEIGHT 10
#define MAX_HEIGHT 30

#define RAW(x, y) (state.cells[y][x])
#define CELL(x, y) RAW(x+1, y+1)

#define MASK_MINE 0x80
#define IS_MINE(x) ((x) & MASK_MINE)
#define SET_MINE(x) ((x) |= MASK_MINE)

#define MASK_FLAG 0x40
#define IS_FLAG(x) ((x) & MASK_FLAG)
#define SET_FLAG(x) ((x) |= MASK_FLAG)
#define CLR_FLAG(x) ((x) &=~MASK_FLAG)
#define TGL_FLAG(x) ((x) ^= MASK_FLAG)

#define MASK_OPEN 0x20
#define IS_OPEN(x) ((x) & MASK_OPEN)
#define SET_OPEN(x) ((x) |= MASK_OPEN)

#define MASK_AROUND 0x0f
#define AROUND(x) ((x) & MASK_AROUND)

typedef struct GAME_STATE {
	int width;
	int height;
	int mines;
	int start;
	int alive;
	int x;
	int y;
	char cells[MAX_HEIGHT + 2][MAX_WIDTH + 2];
} GAME_STATE, *PGAME_STATE;

GAME_STATE state = { 9, 9, 10 };

int cheat_seq[] = {
		KEY_UP,
		KEY_UP,
		KEY_DOWN,
		KEY_DOWN,
		KEY_LEFT,
		KEY_RIGHT,
		KEY_LEFT,
		KEY_RIGHT,
		'b',
		'a',
		'\n'
};

#define CHEAT_COUNT (sizeof(cheat_seq)/sizeof(cheat_seq[0]))

int cheat = 0;

void print_usage(char *cmd) {
	fprintf(stderr,
			"Usage: %s [-s SKILL] [-W WIDTH] [-H HEIGHT] [-M MINES] [-h]\n\
\n\
    -s SKILL    Select a preset dimension and mine count. One of:\n\
                    Beginner:     9x9 with 10 mines. (default)\n\
                    Intermediate: 16x16 with 40 mines.\n\
                    Advanced:     30x16 with 99 mines.\n\
    -W WIDTH    Set the width of the game board.\n\
                Must be between 8 and 30\n\
    -H HEIGHT   Set the height of the game board.\n\
                Must be between 8 and 24\n\
    -M MINES    Set the number of mines.\n\
                Must be between 10 and (WIDTH-1)*(HEIGHT-1)\n\
                Set the WIDTH and HEIGHT first\n\
    -h          Print this help\n\
\n\
Gameplay:\n\
\n\
It's a fairly standard game of minesweeper, except the timer is not displayed\n\
until you win. Refer to other resources for the rules. Here's an example board:\n\
\n\
+                           +---+---+\n\
                          1 | : | : |\n\
                            +---+---+\n\
          1   2   2   1   1 | : | : |\n\
            +---+   +---+---+---+---+\n\
          1 | # |[*]| : | : | : | : |\n\
            +---+---+---+---+---+---+\n\
  1   2   2 | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
| : | : | : | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
| : | : | : | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
| : | : | : | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
| : | : | : | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
| : | : | : | : | : | : | : | : | : |\n\
+---+---+---+---+---+---+---+---+---+\n\
\n\
Concealed cells are indicated by a colon (:).\n\
Flagged cells are indicated by a hash (#).\n\
Mines are indicated by an asterisk (*).\n\
Empty cells are indicated by empty space. These have no mines around them.\n\
Non-empty open cells are indicated by the number of surrounding mines.\n\
The cursor is indicated by brackets [ ] around the cell's contents.\n\
\n\
ARROW KEYS: Navigate the cursor around the board.\n\
SPACE:      Clear a concealed cell, or\n\
            Clear all cells surrounding an open cell. This is only allowed when\n\
              the number of flagged cells surrounding the cursor matches the\n\
              number of surrounding mines indicated by the cell's contents.\n\
F:          Flag a cell believed to conceal a mine, or\n\
            Unflag a cell no longer believed to conceal a mine. A flagged cell\n\
              cannot be cleared.\n\
SHIFT+R:    Start a new game.\n\
CTRL+C:     Quit.\n\
",
			cmd);
}

void timer_func() {
}

#define ARGS_ERR() do { \
	fprintf(stderr, "Invalid argument: %s\n", argv[i]); \
	print_usage(argv[0]); \
	exit(-1); \
} while (0)

#define REQ_ARG(name) do { \
	i++; \
	if (i >= argc) { \
		fprintf(stderr, "Missing argument: %s\n", name); \
		print_usage(argv[0]); \
		exit(-1); \
	} \
} while (0)

void parse_skill(char *arg) {
	if (strcmp("Beginner", arg) == 0) {
		state.width = 9;
		state.height = 9;
		state.mines = 10;
	}
	else if (strcmp("Intermediate", arg) == 0) {
		state.width = 16;
		state.height = 16;
		state.mines = 40;
	}
	else if (strcmp("Advanced", arg) == 0) {
		state.width = 30;
		state.height = 16;
		state.mines = 99;
	}
	else {
		fprintf(stderr, "Invalid SKILL: %s\n", arg);
		exit(-1);
	}
}

unsigned long parse_int(char *a, char *name,
		unsigned long min, unsigned long max) {
	char *e;
	unsigned long val = strtoul(a, &e, 10);
	if (*e != 0 || val < min || max < val) {
		fprintf(stderr, "Invalid %s: %s. Must be an integer between %d and %d.\n",
				name, a, min, max);
		exit(-1);
	}
	return val;
}

void parse_width(char *arg) {
	state.width = parse_int(arg, "WIDTH", 8, 30);
}

void parse_height(char *arg) {
	state.height = parse_int(arg, "HEIGHT", 8, 24);
}

void parse_mines(char *arg) {
	state.mines = parse_int(arg, "MINES", 10, (state.width - 1) * (state.height - 1));
}

void parse_args(int argc, char **argv) {
	if (argc == 0) {
		print_usage("?????");
		exit(-1);
	}
	for (int i = 1; i < argc; i++) {
		if (strnlen(argv[i], 3) != 2 || argv[i][0] != '-') {
			ARGS_ERR();
		}
		switch (argv[i][1]) {
			case 's':
				REQ_ARG("SKILL");
				parse_skill(argv[i]);
				break;
			case 'W':
				REQ_ARG("WIDTH");
				parse_width(argv[i]);
				break;
			case 'H':
				REQ_ARG("HEIGHT");
				parse_height(argv[i]);
				break;
			case 'M':
				REQ_ARG("MINES");
				parse_mines(argv[i]);
				break;
			case 'h':
				print_usage(argv[0]);
				exit(0);
				break;
			default:
				ARGS_ERR();
		}
	}
}

int rand_rng(int n) {
	return rand() % n;
}

int count_around(int X, int Y) {
	int count = 0;
	for (int y = Y - 1; y <= Y + 1; y++) {
		for (int x = X - 1; x <= X + 1; x++) {
			if (IS_MINE(RAW(x,y))) {
				count++;
			}
		}
	}
	return count;
}

int count_flags_around(int X, int Y) {
	int count = 0;
	for (int y = Y - 1; y <= Y + 1; y++) {
		for (int x = X - 1; x <= X + 1; x++) {
			if (IS_FLAG(CELL(x,y))) {
				count++;
			}
		}
	}
	return count;
}

void setup_board() {
	memset(state.cells, 0, sizeof(state.cells));
	for (int mines = 0; mines < state.mines;) {
		int x = rand_rng(state.width);
		int y = rand_rng(state.height);
		if (!IS_MINE(CELL(x,y))) {
			SET_MINE(CELL(x,y));
			mines++;
		}
	}
	for (int y = 1; y <= state.height; y++) {
		for (int x = 1; x <= state.width; x++) {
			if (!IS_MINE(RAW(x,y))) {
				RAW(x,y) |= count_around(x, y);
			}
		}
	}
	for (int y = 1; y <= state.height; y++) {
		SET_OPEN(RAW(0,y));
		SET_OPEN(RAW(state.width+1,y));
	}
	for (int x = 1; x <= state.width; x++) {
		SET_OPEN(RAW(x,0));
		SET_OPEN(RAW(x,state.height+1));
	}
	state.alive = TRUE;
}

void print_grid() {
	for (int y = 0; y <= state.height; y++) {
		for (int x = 0; x <= state.width; x++) {
			move(y * 2, x * 4);
			if (IS_OPEN(RAW(x ,y )) && IS_OPEN(RAW(x+1,y )) &&
					IS_OPEN(RAW(x ,y+1)) && IS_OPEN(RAW(x+1,y+1))) {
				addch(' ');
			}
			else {
				addch('+');
			}
			if (x > 0) {
				move(y * 2, x * 4 - 3);
				if (IS_OPEN(RAW(x,y)) && IS_OPEN(RAW(x,y+1))) {
					addstr("   ");
				}
				else {
					addstr("---");
				}
			}
			if (y > 0) {
				move(y * 2 - 1, x * 4);
				if (IS_OPEN(RAW(x,y)) && IS_OPEN(RAW(x+1,y))) {
					addch(' ');
				}
				else {
					addch('|');
				}
			}
		}
	}
}

int around_attrs[] = {
		A_NORMAL,
		COLOR_PAIR(4) | A_NORMAL,
		COLOR_PAIR(2) | A_NORMAL,
		COLOR_PAIR(1) | A_NORMAL,
		COLOR_PAIR(4) | A_BOLD,
		COLOR_PAIR(5) | A_NORMAL,
		COLOR_PAIR(6) | A_NORMAL,
		COLOR_PAIR(7) | A_DIM,
		COLOR_PAIR(7) | A_NORMAL
};

void display_board() {
	for (int y = 0; y < state.height; y++) {
		for (int x = 0; x < state.width; x++) {
			move(y * 2 + 1, x * 4 + 2);
			if (IS_FLAG(CELL(x,y))) {
				addch('#');
			}
			else if (state.alive && !IS_OPEN(CELL(x,y)) && cheat != CHEAT_COUNT) {
				addch(':');
			}
			else if (IS_MINE(CELL(x,y))) {
				addch('*');
			}
			else {
				int around = AROUND(CELL(x,y));
				if (around == 0) {
					addch(' ');
				}
				else {
					addch('0' + around | around_attrs[around]);
				}
			}
		}
	}
}

void display_cursor() {
	mvaddch(state.y * 2 + 1, state.x * 4 + 1, '[');
	mvaddch(state.y * 2 + 1, state.x * 4 + 3, ']');
	move(state.y * 2 + 1, state.x * 4 + 2);
}

void erase_cursor() {
	mvaddch(state.y * 2 + 1, state.x * 4 + 1, ' ');
	mvaddch(state.y * 2 + 1, state.x * 4 + 3, ' ');
}

void myexit() {
	endwin();
}

void clear_status() {
	mvaddstr(state.height * 2 + 2, 0, "                                          ");
}

void print_status(char *msg) {
	clear_status();
	mvaddstr(state.height * 2 + 2, 0, msg);
}

void print_status_coord(char *msg) {
	clear_status();
	mvprintw(state.height * 2 + 2, 0, "%s (%d,%d)", msg, state.x, state.y);
}

void print_win() {
	clear_status();
	int elapsed = time(NULL) - state.start;
	mvprintw(state.height * 2 + 2, 0, "You win! Score: %d seconds", elapsed);
}

void do_clear_cell(int x, int y);

void clear_around(int x, int y) {
	do_clear_cell(x - 1, y - 1);
	do_clear_cell(x + 0, y - 1);
	do_clear_cell(x + 1, y - 1);

	do_clear_cell(x - 1, y + 0);
	// Skip (x, y)
	do_clear_cell(x + 1, y + 0);

	do_clear_cell(x - 1, y + 1);
	do_clear_cell(x + 0, y + 1);
	do_clear_cell(x + 1, y + 1);
}

void do_clear_cell(int x, int y) {
	if (!state.alive) {
		return;
	}
	if (x == -1 || y == -1 || x == state.width || y == state.height) {
		return;
	}
	if (!IS_FLAG(CELL(x,y)) && !IS_OPEN(CELL(x,y))) {
		SET_OPEN(CELL(x,y));
		if (IS_MINE(CELL(x,y))) {
			print_status_coord("Tripped mine at");
			state.alive = FALSE;
			return;
		}
		if (AROUND(CELL(x,y)) == 0) {
			clear_around(x, y);
		}
	}
}

void super_clear(int x, int y) {
	if (!state.alive) {
		return;
	}
	if (count_flags_around(x, y) == AROUND(CELL(x,y))) {
		clear_around(x, y);
		if (state.alive) {
			print_status_coord("Super cleared");
		}
	}
	else {
		print_status_coord("Incorrect flag number around");
	}
}

void clear_cell(int x, int y) {
	if (state.start == 0) {
		state.start = time(NULL);
	}
	if (IS_FLAG(CELL(x,y))) {
		print_status_coord("Cannot clear flagged cell");
	}
	else if (IS_OPEN(CELL(x,y))) {
		super_clear(x, y);
	}
	else {
		do_clear_cell(x, y);
		if (state.alive) {
			print_status_coord("Cleared");
		}
	}
}

void flag_cell(int x, int y) {
	if (!state.alive) {
		return;
	}
	if (IS_OPEN(CELL(x,y))) {
		return;
	}
	if (IS_FLAG(CELL(x,y))) {
		print_status_coord("Removed flag");
		CLR_FLAG(CELL(x,y));
	}
	else {
		print_status_coord("Flagged cell");
		SET_FLAG(CELL(x,y));
	}
}

void check_win() {
	for (int y = 0; y < state.height; y++) {
		for (int x = 0; x < state.width; x++) {
			int c = CELL(x, y);
			if (!IS_OPEN(c) && !IS_MINE(c)) {
				return;
			}
		}
	}
	print_win();
	state.alive = FALSE;
}

int main(int argc, char **argv) {
	parse_args(argc, argv);

	srand(0x5eed0000 | 0x0000ffff & time(NULL));
	setup_board();

	initscr();
	atexit(myexit);
	noecho();
	keypad(stdscr, TRUE);
	start_color();
	init_pair(1, COLOR_RED, COLOR_BLACK);
	init_pair(2, COLOR_GREEN, COLOR_BLACK);
	init_pair(3, COLOR_YELLOW, COLOR_BLACK);
	init_pair(4, COLOR_BLUE, COLOR_BLACK);
	init_pair(5, COLOR_MAGENTA, COLOR_BLACK);
	init_pair(6, COLOR_CYAN, COLOR_BLACK);
	init_pair(7, COLOR_WHITE, COLOR_BLACK);

	while (1) {
		print_grid();
		display_board();
		display_cursor();

		refresh();
		int ch = getch();
		erase_cursor();
		switch (ch) {
			case 'R':
				setup_board();
				print_status("Reset");
				cheat = 0;
				break;
			case KEY_LEFT:
				if (state.x > 0)
					state.x--;
				break;
			case KEY_RIGHT:
				if (state.x < state.width - 1)
					state.x++;
				break;
			case KEY_UP:
				if (state.y > 0)
					state.y--;
				break;
			case KEY_DOWN:
				if (state.y < state.height - 1)
					state.y++;
				break;
			case ' ':
				clear_cell(state.x, state.y);
				check_win();
				break;
			case 'f':
				flag_cell(state.x, state.y);
				break;
		}
		if (cheat == CHEAT_COUNT) {
		}
		else if (ch == cheat_seq[cheat]) {
			cheat++;
		}
		else {
			cheat = 0;
		}
	}
}

