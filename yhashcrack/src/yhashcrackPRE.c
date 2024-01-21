//
#include <omp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

//
#include "types.h"

//
#include "yhash/yhash.h"

//
#define LOAD_NB 100000000

//
typedef struct dictionary_s {
	// List of passwords
	ascii **list;

	// Number of entries
	u64 n;

	//
	u64 max_n;

	//
	u64 size;

	//
	u64 rounds;

} dictionary_t;

//
typedef struct thread_task_s {
	// Pointer to the thread block of the dictionary
	ascii **list;

	// Number of passwords in the block
	u64 n;

	// Thread ID
	pthread_t tid;

	// The hash to crack
	u8 *target_hash;

	// The hash length
	u64 hash_len;

	// The hash function
	void (*hash_function)(const u8 *, const u64, u8 *);

	//
	u8 found;

	// The password (if found)
	ascii *password;

} thread_task_t;

//
ascii yhashcrack_logo[] =

	"     _____         _   _____             _   \n"
	" _ _|  |  |___ ___| |_|     |___ ___ ___| |_ \n"
	"| | |     | .'|_ -|   |   --|  _| .'|  _| '_|\n"
	"|_  |__|__|__,|___|_|_|_____|_| |__,|___|_,_|\n"
	"|___|                                        \n";

//

//
ascii *import_file_data(ascii *path, u64 file_len) {
	FILE *fp = fopen(path, "rb");

	if (!fp) {
		printf("Error: cannot open file '%s'\n", path);
		exit(4);
	}

	ascii *file_data = aligned_alloc(8, file_len + 1);

	if (fread(file_data, 1, file_len, fp) < file_len) {
		exit(9);
	}

	file_data[file_len] = '\0';

	fclose(fp);

	return file_data;
}

dictionary_t *create_dictionary(u64 max_n, u64 max_len) {
	dictionary_t *d = malloc(sizeof(dictionary_t));

	if (!d)
		return printf("Error: cannot allocate dictionary\n"), NULL;

	d->list = malloc(sizeof(ascii *) * max_n);

	if (!d->list)
		return printf("Error: cannot allocate dictionary list\n"), NULL;

	d->n = 0;
	d->max_n = max_n;
	d->size = 0;
	d->rounds = 0;

	for (u64 i = 0; i < max_n; i++) {
		d->list[i] = aligned_alloc(16, sizeof(ascii) * max_len);

		if (!d->list[i]) {
			printf("Error: cannot allocate password entry '%llu' in dictionary\n", i);
			exit(7);
		}
	}

	return d;
}

//
void destroy_dictionary(dictionary_t *d) {
	if (d) {
		for (u64 i = 0; i < d->max_n; i++)
			free(d->list[i]);

		free(d->list);

		d->n = 0;
		d->max_n = 0;
		d->size = 0;
		d->rounds = 0;
	} else
		printf("Error: dictionary pointer is NULL\n"), exit(5);
}

// Unused
void parser(ascii *str) {
	u64 str_len = strlen(str);

	for (u64 i = 0; i < str_len; ++i) {
		if (str[i] < 33 || str[i] == 127) {
			for (u64 j = i; j < str_len; ++j) {
				str[j] = str[j + 1];
			}
			str_len--;
			i--;
		}
	}

	str[str_len] = '\0';
}

//
ascii *get_data(ascii *storage, ascii *data, u64 *position_data) {
	if (data[*position_data] == '\0') {
		return NULL;
	}

	u64 i = 0;

	while (data[*position_data] == 10) {
		(*position_data)++;
	}

	for (i = 0; i < 32; ++i) {
		if (data[*position_data] == 10) {
			break;
		}

		storage[i] = data[*position_data];
		(*position_data)++;
	}

	storage[i] = '\0';

	(*position_data)++;
	// parser(storage);

	return storage;
}

//
ascii load_dictionary(ascii *file_data, dictionary_t *d, u64 *position_data) {
	u64 i = 0;
	ascii *done = NULL;
	f64 elapsed = 0.0;
	f64 after = 0.0, before = 0.0;
	ascii *buffer = malloc((sizeof(ascii) * 32) + 1);

	if (file_data) {
		printf("Loading dictionary block");
		fflush(stdout);

		before = omp_get_wtime();

		for (i = 0; (i < d->max_n) && (done = get_data(buffer, file_data, position_data)) != NULL; ++i) {
			printf("%s\n", buffer);
			strcpy(d->list[i], buffer);
			d->size += strlen(d->list[i]);
		}

		after = omp_get_wtime();

		d->n = i;

		elapsed = (after - before);

		f64 bw = ((f64)d->size) / (elapsed * 1e9);

		printf(" (%llu MiB) in %.3lf s - %.3lf GiB/s\n", d->size >> 20, elapsed, bw);
	}

	free(buffer);

	return (done == NULL) ? 0 : 1;
}

// Convert a string to a hash
void str_to_hash(ascii *str, u8 *hash, u64 str_len) {
	u8 b;
	static u8 cvt_tab[6] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

	for (u64 i = 0, j = 0; i < str_len; i += 2, j++) {
		b = 0x00;

		// High 4 bits
		if (str[i] >= '0' && str[i] <= '9')
			b = (str[i] - '0') << 4;
		else if (str[i] >= 'A' && str[i] <= 'F')
			b = cvt_tab[str[i] - 'A'] << 4;
		else if (str[i] >= 'a' && str[i] <= 'f')
			b = cvt_tab[str[i] - 'a'] << 4;

		// Low 4 bits
		if (str[i + 1] >= '0' && str[i + 1] <= '9')
			b |= (str[i + 1] - '0') & 0x0F;
		else if (str[i + 1] >= 'A' && str[i + 1] <= 'F')
			b |= cvt_tab[str[i + 1] - 'A'] & 0x0F;
		else if (str[i + 1] >= 'a' && str[i + 1] <= 'f')
			b |= cvt_tab[str[i + 1] - 'a'] & 0x0F;

		// Store byte
		hash[j] = b;
	}
}

//
void print_hash(const u8 *hash, u64 hash_len) {
	for (u64 i = 0; i < hash_len; i++)
		printf("%02x", hash[i]);

	printf("\n");
}

//
u8 compare(u8 *restrict hash1, u8 *restrict hash2) {
	u64 d __attribute__((aligned(32))) = 0;

	__asm__ volatile(
		"vxorpd %%ymm0, %%ymm0, %%ymm0;\n"
		"vxorpd %%ymm1, %%ymm1, %%ymm1;\n"
		"vmovdqa (%[_hash1]), %%ymm0;\n"
		"vmovdqa (%[_hash2]), %%ymm1;\n"

		"vpxor %%ymm1, %%ymm0, %%ymm0;\n"

		"vmovdqa %%ymm0, (%[_d]);\n"

		:  // outputs

		:  // inputs
		[_hash1] "r"(hash1),
		[_hash2] "r"(hash2),
		[_d] "r"(&d)

		:  // clobbers
		"cc", "memory", "ymm0", "ymm1");
	//

	return (d) ? 0 : 1;
}

//
void *thread_task(void *arg) {
	thread_task_t *tt = (thread_task_t *)arg;

	u8 found = 0;
	ascii **list = tt->list;
	u8 *target_hash = tt->target_hash;
	u64 hash_len = tt->hash_len;
	u8 hash[hash_len];

	// void (*hash_function)(const u8 *, const u64, u8 *) = tt->hash_function;

	for (u64 i = 0; i < tt->n; i++) {
		// hash_function((u8 *)list[i], strlen(list[i]), hash);

		found = compare(target_hash, hash);

		if (found) {
			tt->found = 1;
			tt->password = list[i];
			break;
		}
	}

	if (!found)
		tt->password = NULL;

	return NULL;
}

//
u8 lookup_hash_parallel(u64 nt, dictionary_t *d, u8 *target_hash, void (*hash_function)(const u8 *, const u64, u8 *), const u64 hash_len, ascii **password) {
	u8 found = 0;
	u64 thread_n = d->n / nt;
	u64 thread_m = d->n % nt;
	thread_task_t *tt = malloc(sizeof(thread_task_t) * nt);

	if (!tt) {
		printf("Error: cannot allocate memory for threads\n");
		exit(6);
	}

	for (u64 i = 0; i < nt; i++) {
		tt[i].n = (thread_n + ((i == nt - 1) ? thread_m : 0));
		tt[i].list = &d->list[i * thread_n];
		tt[i].hash_function = hash_function;
		tt[i].target_hash = target_hash;
		tt[i].hash_len = hash_len;
		tt[i].found = 0;
		tt[i].password = NULL;

		pthread_create(&tt[i].tid, NULL, thread_task, &tt[i]);
	}

	for (u64 i = 0; i < nt; i++) {
		pthread_join(tt[i].tid, NULL);

		if (tt[i].found) {
			(*password) = tt[i].password;
			found = 1;
		}
	}

	free(tt);

	return found;
}

//
void pre_hash(ascii *input, ascii *output, u64 file_len) {
	FILE *fi = fopen(input, "rb");
	FILE *fo = fopen(output, "wb");

	ascii done = 0;
	ascii *buffer = malloc((sizeof(ascii) * 32) + 2);
	u8 hash[SHA256_HASH_SIZE+1];

	if (fi) {
		for (u64 i = 0; i < file_len; ++i) {
			done = fscanf(fi, "%s\n", buffer);

			if (done == EOF) {
				break;
			}

			sha256hash((u8 *)buffer, strlen(buffer), hash);
			fwrite(hash, (strlen(buffer) + 1), sizeof(ascii), fo);
			fputc('\n', fo);
		}

		free(buffer);
		fclose(fi);
		fclose(fo);
	}
}

//
int main(int argc, char **argv) {
	// Print logo
	printf("%s\n", yhashcrack_logo);

	// Handle command line parameters
	if (argc < 4)
		return printf("Usage: %s [hashing algorithm] [number of threads] [dictionary path] [hash]\n", argv[0]), 1;

	// Set hash length and hash function pointer
	u64 hash_len = 0;
	void (*hash_function)(const u8 *, const u64, u8 *) = NULL;
	;

	if (!strcmp(argv[1], "md5")) {
		hash_len = MD5_HASH_SIZE;
		hash_function = md5hash;
	} else if (!strcmp(argv[1], "sha1")) {
		hash_len = SHA1_HASH_SIZE;
		hash_function = sha1hash;
	} else if (!strcmp(argv[1], "sha224")) {
		hash_len = SHA224_HASH_SIZE;
		hash_function = sha224hash;
	} else if (!strcmp(argv[1], "sha256")) {
		hash_len = SHA256_HASH_SIZE;
		hash_function = sha256hash;
	} else if (!strcmp(argv[1], "sha512")) {
		hash_len = SHA512_HASH_SIZE;
		hash_function = sha512hash;
	} else {
		printf("Error: unknown hashing algorithm '%s'\n", argv[1]);
		exit(8);
	}

	// Get number of threads
	u64 nt = atoll(argv[2]);

	if (nt < 1)
		return printf("Error: invalid number of threads '%llu'\n", nt), 4;

	// Printing info
	printf(
		"Number of threads   : %llu\n"
		"Hashing algorithm   : %s\n"
		"Target hash         : %s\n"
		"Dictionary file     : %s\n",
		nt, argv[1], argv[4], argv[3]);

	// Get file size
	u64 size = 0;
	struct stat sb;
	u64 dictionary_size = 0;
	ascii *file_data = NULL;
	u64 position_data = 0;

	if (stat(argv[3], &sb) < 0)
		return printf("Error: cannot open file '%s'\n", argv[3]), 3;

	dictionary_size = sb.st_size;

	file_data = import_file_data(argv[3], sb.st_size);

	u8 found = 0;
	ascii *password = NULL;
	u8 target_hash[hash_len];
	f64 lu_after = 0.0, lu_before = 0.0;
	f64 all_after = 0.0, all_before = 0.0;

	// Convert parameter hash (string) into number form
	str_to_hash(argv[4], target_hash, strlen(argv[4]));

	// pre_hash("dictionary/passwords.txt", "dictionary/passwordsHASHED.txt", sb.st_size);
	// exit(0);

	dictionary_t *d = create_dictionary(LOAD_NB, 32);

	if (!d)
		return printf("Error: cannot create dictionary\n"), 4;

	printf("Dictionary file size: %llu MiB; %llu GiB\n\n", dictionary_size >> 20, dictionary_size >> 30);

	all_before = omp_get_wtime();

	while (load_dictionary(file_data, d, &position_data) != EOF) {
		lu_before = omp_get_wtime();

		found = lookup_hash_parallel(nt, d, target_hash, hash_function, hash_len, &password);

		lu_after = omp_get_wtime();

		f64 lu_elapsed = (lu_after - lu_before);

		// Total searched memory size
		size += d->size;

		f64 bw = ((f64)d->size) / (lu_elapsed * 1e9);

		printf("Hashed and compared %llu passwords (%llu MiB), in %.3lf seconds; %.3lf GiB/s\n\n", d->n, d->size >> 20, lu_elapsed, bw);

		if (found)
			break;

		d->size = 0;
		d->rounds++;
	}

	all_after = omp_get_wtime();

	if (found)
		printf("### Cracked :]  password: '%s'\n\n", password);
	else
		printf("### Sorry! No password matched the given %s hash\n\n", argv[1]);

	f64 all_elapsed = (all_after - all_before);

	printf("Cracking run time: %.3lf seconds, %.3lf minutes; Number of rounds: %llu; Searched memory: ", all_elapsed, all_elapsed / 60.0, d->rounds);

	if ((size >> 20) > 1024)
		printf("%.3lf GiB\n", (f64)size / (1024 * 1024 * 1024));
	else
		printf("%.3lf MiB\n", (f64)size / (1024 * 1024));

	free(file_data);
	destroy_dictionary(d);
	free(d);

	return 0;
}
