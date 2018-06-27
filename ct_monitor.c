/* ct_monitor - Certificate Transparency Log Monitor
 * Written by Rob Stradling
 * Copyright (C) 2015-2017 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <libpq-fe.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <unistd.h>

#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

#include "curl/curl.h"

#include "json-c/json.h"


#define CURL_EASY_SETOPT(NAME, VALUE)					\
	t_curlCode = curl_easy_setopt(t_hEasy, NAME, VALUE);		\
	if (t_curlCode != CURLE_OK) {					\
		printError(						\
			"curl_easy_setopt: "#NAME,			\
			curl_easy_strerror(t_curlCode)			\
		);							\
		goto label_exit;					\
	}

#ifdef __LP64__
	/* 64-bit */
	#define LENGTH32	""
	#define LENGTH64	"l"
#else
	/* 32-bit */
	#define LENGTH32	"l"
	#define LENGTH64	"ll"
#endif


typedef struct tDataBuffer {
	char* data;
	size_t size;
} tDataBuffer;


static int g_terminateNow = 0;


/******************************************************************************
 * printError()                                                               *
 ******************************************************************************/
static void printError(
	const char* const v_errorMessage1,	/* IN */
	const char* const v_errorMessage2	/* IN */
)
{
	time_t t_now;
	char t_now_string[27];
	char* t_offset;

	/* Convert the current date/time to a string */
	t_now = time(NULL);
	(void)ctime_r(&t_now, t_now_string);

	/* Strip trailing LF characters from the date/time string */
	for (t_offset = t_now_string + strlen(t_now_string) - 1;
			(t_offset > t_now_string) && (*t_offset == '\n');
			t_offset--)
		*t_offset = '\0';

	/* Output the error line to stderr */
	fprintf(stderr, "%s: %s", t_now_string, v_errorMessage1);
	if (v_errorMessage2)
		fprintf(stderr, " (%s)", v_errorMessage2);
	fprintf(stderr, "\n");
	fflush(stderr);
}


/******************************************************************************
 * signalHandler()                                                            *
 ******************************************************************************/
static void signalHandler(
	const int v_signalNumber		/* IN */
)
{
	printError(
		"Signal received",
		(v_signalNumber == SIGHUP) ? "SIGHUP" :
			((v_signalNumber == SIGINT) ? "SIGINT" :
				((v_signalNumber == SIGQUIT) ? "SIGQUIT" :
								"SIGTERM"))
	);

	g_terminateNow = 1;
}


int calcDecodeLength(const char* b64input) { /*Calculates the length of a decoded base64 string*/
  int len = strlen(b64input);
  int padding = 0;
 
  if (b64input[len-1] == '=' && b64input[len-2] == '=') /*last two chars are =*/
    padding = 2;
  else if (b64input[len-1] == '=') /*last char is =*/
    padding = 1;
 
  return (int)len*0.75 - padding;
}
 
int Base64Decode(char* b64message, char** buffer) { /*Decodes a base64 encoded string*/
  BIO *bio, *b64;
  FILE* stream;
  int decodeLen = calcDecodeLength(b64message),
      len = 0;
  *buffer = (char*)malloc(decodeLen+1);
  stream = fmemopen(b64message, strlen(b64message), "r");
 
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); /*Do not use newlines to flush buffer*/
  len = BIO_read(bio, *buffer, strlen(b64message));
    /*Can test here if len == decodeLen - if not, then return an error*/
  (*buffer)[len] = '\0';
 
  BIO_free_all(bio);
  fclose(stream);
 
  return (0); /*success*/
}


size_t curlDataReceivedFunction(
	char* v_dataBuffer,
	size_t v_dataSize,
	size_t v_dataSizeMultiplier,
	void* v_responseBuffer
)
{
#define t_responseBuffer	((tDataBuffer*)v_responseBuffer)
	size_t t_dataSize = v_dataSize * v_dataSizeMultiplier;

	/* Resize the response buffer */
	t_responseBuffer->data = (char*)realloc(
		t_responseBuffer->data, t_responseBuffer->size + t_dataSize + 1
	);

	/* Append this block of received data */
	memcpy(
		t_responseBuffer->data + t_responseBuffer->size,
		v_dataBuffer, t_dataSize
	);

	/* Update the size */
	t_responseBuffer->size += t_dataSize;

	/* NULL-terminate (the NULL-terminator is not included in the size) */
	t_responseBuffer->data[t_responseBuffer->size] = '\0';

	return t_dataSize;
#undef t_responseBuffer
}


static int compareSHA256Hashes(
	const void* v_sha256Hash1,
	const void* v_sha256Hash2
)
{
	return memcmp(v_sha256Hash1, v_sha256Hash2, 32);
}


int main(
	int argc,
	char** argv
)
{
	PGconn* t_PGconn = NULL;
	PGresult* t_PGresult_select = NULL;
	PGresult* t_PGresult;
	int t_returnCode = EXIT_FAILURE;
	int i = -1;
	int j;
	int k;
	int q;

	CURLcode t_curlCode;
	CURL* t_hEasy = NULL;
	char t_curlErrorMessage[CURL_ERROR_SIZE];
	tDataBuffer t_responseBuffer = { NULL, 0 };
	long t_httpResponseCode;

	json_object* j_getSTH = NULL;
	json_object* j_treeSize = NULL;
	json_object* j_timestamp = NULL;
	json_object* j_getEntries = NULL;
	json_object* j_entries = NULL;
	json_object* j_entry = NULL;
	json_object* j_leafInput = NULL;
	json_object* j_extraData = NULL;
	array_list* t_entriesArr = NULL;
	uint32_t t_entryID;
	uint32_t t_batchSize;
	uint32_t t_confirmedEntryID = -1;
	uint64_t t_timestamp;
	int64_t t_sthTimestamp;
	int64_t t_treeSize;
	uint16_t t_logEntryType;
	char t_temp[255];
	char* t_pointer;
	char* t_pointer1;
	char* t_b64Data;
	char* t_data = NULL;
	int32_t t_totalLength;

	X509* t_x509 = NULL;
	uint32_t t_certSize;
	char* t_query[32];
	char* t_subjectName;

	uint8_t* t_cachedCACerts = NULL;
	uint32_t t_nCachedCACerts = 0;
	uint32_t t_nCertsInChain;
	EVP_MD_CTX t_mdctx;
	const EVP_MD* t_md;
	unsigned char t_sha256Hash_data[32];
	uint32_t t_sha256Hash_size;

	/* Initialize the OpenSSL library */
	OpenSSL_add_all_algorithms();
	t_md = EVP_sha256();
	EVP_MD_CTX_init(&t_mdctx);

	/* Install signal handlers */
	signal(SIGHUP, signalHandler);
	signal(SIGINT, signalHandler);
	signal(SIGQUIT, signalHandler);
	signal(SIGTERM, signalHandler);

	for (q = 0; q < 32; q++)
		t_query[q] = malloc(128 * 1024);

	/* Connect to the database */
	t_PGconn = PQconnectdb(
		"user=crtsh dbname=certwatch"
			" connect_timeout=5 client_encoding=auto"
			" application_name=ct_monitor"
	);
	if (PQstatus(t_PGconn) != CONNECTION_OK) {
		printError("PQconnectdb()", PQerrorMessage(t_PGconn));
		return EXIT_FAILURE;
	}

	printError("Connected OK", NULL);

	/* Get the latest CT Entry ID that we've added to the DB already */
	sprintf(
		t_query[0],
		"SELECT ctl.ID, ctl.URL, ctl.NAME, coalesce(ctl.BATCH_SIZE, 256)"
			" FROM ct_log ctl"
			" WHERE ctl.IS_ACTIVE"
	);
	if (argc > 1)	/* Only process one log */
		sprintf(
			t_query[0] + strlen(t_query[0]),
				" AND ctl.ID = %s",
			argv[1]
		);
	else		/* Process all logs */
		strcat(
			t_query[0],
			" ORDER BY ctl.ID"
		);

	t_PGresult_select = PQexec(
		t_PGconn, t_query[0]
	);
	if (PQresultStatus(t_PGresult_select) != PGRES_TUPLES_OK) {
		/* The SQL query failed */
		printError("Query failed", PQerrorMessage(t_PGconn));
		goto label_exit;
	}

	/* curl_global_init() must be called EXACTLY once */
	t_curlCode = curl_global_init(CURL_GLOBAL_ALL);
	if (t_curlCode != CURLE_OK) {
		printError(
			"curl_global_init()", curl_easy_strerror(t_curlCode)
		);	/* Something went wrong, so we cannot continue */
		return EXIT_FAILURE;
	}

	for (i = 0; i < PQntuples(t_PGresult_select); i++) {
		t_confirmedEntryID = -1;

		/* Initialize the "easy handle" */
		t_hEasy = curl_easy_init();
		if (!t_hEasy) {
			printError("curl_easy_init()", "returned NULL");
			goto label_exit;
		}

		/* SETUP CURL BEHAVIOUR OPTIONS */
		/* CURLOPT_NOPROGRESS: No progress meter */
		CURL_EASY_SETOPT(CURLOPT_NOPROGRESS, 0)
		/* CURLOPT_NOSIGNAL: Don't use signals */
		CURL_EASY_SETOPT(CURLOPT_NOSIGNAL, 1)

		/* SETUP CURL CALLBACK OPTIONS */
		/* CURLOPT_WRITEFUNCTION: "Data Received" Callback Function */
		CURL_EASY_SETOPT(CURLOPT_WRITEFUNCTION, curlDataReceivedFunction)
		/* CURLOPT_WRITEDATA: Data Pointer to pass to "Data Received" Callback
		  Function */
		CURL_EASY_SETOPT(CURLOPT_WRITEDATA, &t_responseBuffer)

		/* SETUP CURL ERROR OPTIONS */
		/* CURLOPT_ERRORBUFFER: Buffer for potential error message */
		CURL_EASY_SETOPT(CURLOPT_ERRORBUFFER, t_curlErrorMessage)

		/* SETUP CURL NETWORK OPTIONS */
		/* CURLOPT_URL: The URL to deal with */
		sprintf(t_temp, "%s/ct/v1/get-sth",
			PQgetvalue(t_PGresult_select, i, 1));
		printError(t_temp, PQgetvalue(t_PGresult_select, i, 2));
		CURL_EASY_SETOPT(CURLOPT_URL, t_temp)

		/* SETUP CURL HTTP OPTIONS */
		/* CURLOPT_FOLLOWLOCATION: Don't follow "Location:" redirects */
		CURL_EASY_SETOPT(CURLOPT_FOLLOWLOCATION, 0)

		/* SETUP CURL CONNECTION OPTIONS */
		/* CURLOPT_TIMEOUT: Transfer Timeout (in seconds) */
		CURL_EASY_SETOPT(CURLOPT_TIMEOUT, 300)
		/* CURLOPT_CONNECTTIMEOUT: Connect Timeout (in seconds) */
		CURL_EASY_SETOPT(CURLOPT_CONNECTTIMEOUT, 300)

		/* Perform the transfer */
		t_curlCode = curl_easy_perform(t_hEasy);
		if (t_curlCode != CURLE_OK) {
			printError("curl_easy_perform()", t_curlErrorMessage);
			goto label_exit;
		}

		/* Get the HTTP response code */
		t_curlCode = curl_easy_getinfo(
			t_hEasy, CURLINFO_RESPONSE_CODE, &t_httpResponseCode
		);
		if (t_curlCode != CURLE_OK) {
			printError("curl_easy_getinfo()", t_curlErrorMessage);
			goto label_exit;
		}
		else if (t_httpResponseCode != 200) {
			printError(
				"curl_easy_getinfo()", "Unexpected HTTP Response Code"
			);
			goto label_exit;
		}

		/* Get the latest CT Entry ID we've previously obtained for this log */
		sprintf(
			t_query[0],
			"SELECT max(ctle.ENTRY_ID)"
				" FROM ct_log_entry ctle"
				" WHERE ctle.CT_LOG_ID = %s",
			PQgetvalue(t_PGresult_select, i, 0)
		);
		PGresult* t_PGresult_maxEntryID = PQexec(
			t_PGconn, t_query[0]
		);
		if (PQresultStatus(t_PGresult_maxEntryID) != PGRES_TUPLES_OK) {
			/* The SQL query failed */
			printError("Query failed", PQerrorMessage(t_PGconn));
			goto label_exit;
		}
		if (PQgetisnull(t_PGresult_maxEntryID, i, 0))
			t_entryID = -1;
		else
			t_entryID = strtoul(
				PQgetvalue(t_PGresult_maxEntryID, i, 0), NULL, 10
			);
		PQclear(t_PGresult_maxEntryID);
		printf("Highest Entry ID stored: %d\n", t_entryID);

		t_batchSize = strtoul(
			PQgetvalue(t_PGresult_select, i, 3), NULL, 10
		);
		printf("Batch size (end - start): %u\n", t_batchSize);

		j_getSTH = json_tokener_parse(t_responseBuffer.data);
		if (!json_object_object_get_ex(j_getSTH, "tree_size", &j_treeSize))
			goto label_exit;
		t_treeSize = json_object_get_int64(j_treeSize);
		printf("Current Tree Size: %" LENGTH64 "d\n", t_treeSize);
		if (!json_object_object_get_ex(j_getSTH, "timestamp", &j_timestamp))
			goto label_exit;
		t_sthTimestamp = json_object_get_int64(j_timestamp);
		printf("Timestamp: %" LENGTH64 "d\n", t_sthTimestamp);

		if (json_object_put(j_getSTH) != 1) {
			printError("json_object_put(j_getSTH)", "Did not return 1");
			goto label_exit;
		}

		free(t_responseBuffer.data);
		t_responseBuffer.data = NULL;
		t_responseBuffer.size = 0;

		/* TODO: Verify the STH signature */

		/* Update "Last Contacted" and "Latest STH" timestamps, and the "Tree Size" */
		sprintf(
			t_query[0],
			"UPDATE ct_log"
				" SET LATEST_UPDATE=statement_timestamp() AT TIME ZONE 'UTC',"
					" TREE_SIZE=%" LENGTH64 "d,"
					" LATEST_STH_TIMESTAMP=(TIMESTAMP WITH TIME ZONE 'epoch'"
						" + interval'%" LENGTH64 "d seconds'"
						" + interval'%" LENGTH64 "d milliseconds') AT TIME ZONE 'UTC'"
				" WHERE ID=%s",
			t_treeSize,
			t_sthTimestamp / 1000,
			t_sthTimestamp % 1000,
			PQgetvalue(t_PGresult_select, i, 0)
		);
		t_PGresult = PQexec(t_PGconn, t_query[0]);
		if (PQresultStatus(t_PGresult) != PGRES_COMMAND_OK) {
			/* The SQL query failed */
			printError(
				"UPDATE Query failed",
				PQerrorMessage(t_PGconn)
			);
		}
		PQclear(t_PGresult);

		for (t_entryID++; t_entryID < t_treeSize; t_entryID = t_confirmedEntryID + 1) {
			sprintf(
				t_temp, "%s/ct/v1/get-entries?start=%d&end=%" LENGTH64 "d",
				PQgetvalue(t_PGresult_select, i, 1), t_entryID,
				(t_treeSize > (t_entryID + t_batchSize - 1)) ?
					(t_entryID + t_batchSize - 1) : (t_treeSize - 1)
			);
			printError(t_temp, NULL);

			CURL_EASY_SETOPT(CURLOPT_URL, t_temp)

			/* Perform the transfer */
			t_curlCode = curl_easy_perform(t_hEasy);
			if (t_curlCode != CURLE_OK) {
				printError("curl_easy_perform()", t_curlErrorMessage);
				goto label_exit;
			}

			/* Get the HTTP response code */
			t_curlCode = curl_easy_getinfo(
				t_hEasy, CURLINFO_RESPONSE_CODE, &t_httpResponseCode
			);
			if (t_curlCode != CURLE_OK) {
				printError("curl_easy_getinfo()", t_curlErrorMessage);
				goto label_exit;
			}
			else if (t_httpResponseCode != 200) {
				printError(
					"curl_easy_getinfo()",
					"Unexpected HTTP Response Code"
				);
				goto label_exit;
			}

			/* Update the "Last Contacted" timestamp and the "Latest Entry ID" */
			sprintf(
				t_query[0],
				"UPDATE ct_log"
					" SET LATEST_UPDATE=statement_timestamp() AT TIME ZONE 'UTC',"
						" LATEST_ENTRY_ID=%" LENGTH32 "d"
					" WHERE ID=%s",
				t_entryID - 1,
				PQgetvalue(t_PGresult_select, i, 0)
			);
			t_PGresult = PQexec(t_PGconn, t_query[0]);
			if (PQresultStatus(t_PGresult) != PGRES_COMMAND_OK) {
				/* The SQL query failed */
				printError(
					"UPDATE Query failed",
					PQerrorMessage(t_PGconn)
				);
			}
			PQclear(t_PGresult);

			/* Parse the JSON response */
			j_getEntries = json_tokener_parse(t_responseBuffer.data);
			if (!json_object_object_get_ex(j_getEntries, "entries",
							&j_entries))
				goto label_exit;

			t_entriesArr = json_object_get_array(j_entries);

			for (j = 0; j < json_object_array_length(j_entries); j++) {
				j_entry = array_list_get_idx(t_entriesArr, j);

				if (!json_object_object_get_ex(j_entry, "leaf_input",
								&j_leafInput))
					goto label_exit;

				/* Decode the Base64 leaf_input string */
				t_b64Data = (char*)json_object_get_string(j_leafInput);
				t_data = NULL;
				Base64Decode(t_b64Data, &t_data);
				if (!t_data) {
					printError("Base64 decode error", "");
					goto label_exit;
				}

				/* Check the header fields */
				if (*(unsigned char*)t_data != 0) {
					sprintf(
						t_temp, "%u", *(unsigned char*)t_data
					);
					printError("Unexpected Version", t_temp);
					goto label_exit;
				}
				if (*(unsigned char*)(t_data + 1) != 0) {
					sprintf(
						t_temp, "%u", *(unsigned char*)(t_data + 1)
					);
					printError("Unexpected MerkleLeafType", t_temp);
					goto label_exit;
				}

				t_timestamp = be64toh(*(uint64_t*)(t_data + 2));

				t_logEntryType = be16toh(*(uint16_t*)(t_data + 10));
				if (t_logEntryType == 1) {
					/* Precertificate.  The leaf_input contains a
					SHA-256 hash of the Issuer Public Key, then
					the TBSCertificate.  Ignore both of these.
					The submitted Precertificate is the first
					cert in the extra_data */
				}
				else if (t_logEntryType == 0) {
					/* Parse the certificate */
					t_certSize = 0;
					memcpy(((char*)&t_certSize) + 1, t_data + 12, 3);
					t_certSize = be32toh(t_certSize);

					printf("%d: ", (t_entryID + j));

					t_pointer = t_data + 15;
					t_x509 = d2i_X509(
						NULL, (const unsigned char**)&t_pointer,
						t_certSize
					);
					if (t_x509) {
						t_subjectName = X509_NAME_oneline(
							X509_get_subject_name(t_x509), NULL, 0
						);
						if (t_subjectName) {
							printf("%s\n", t_subjectName);
							OPENSSL_free(t_subjectName);
						}
						X509_free(t_x509);
						if (t_certSize != (t_pointer - (t_data + 15))) {
							printError("Additional data after EE cert", t_b64Data);
							t_certSize = t_pointer - (t_data + 15);
						}
					}
					else
						printError("Failed to decode EE cert", t_b64Data);


					/* Construct the "INSERT" query */
					sprintf(t_query[0],
						"SELECT import_ct_cert(%s::smallint, %d, %"
							LENGTH64 "u, E'\\\\x",
						PQgetvalue(t_PGresult_select, i, 0),
						(t_entryID + j), t_timestamp);

					for (k = 0; k < t_certSize; k++)
						sprintf(
							t_query[0] + strlen(t_query[0]), "%02X",
							*(unsigned char*)(t_data + 15 + k));
					strcat(t_query[0], "')");
				}
				else {
					sprintf(t_temp, "%u", t_logEntryType);
					printError("Unexpected LogEntryType", t_temp);
					goto label_exit;
				}

				free(t_data);

				t_nCertsInChain = 1;

				if (!json_object_object_get_ex(j_entry, "extra_data",
								&j_extraData))
					goto label_addCerts;

				/* Decode the Base64 extra_data string */
				t_b64Data = (char*)json_object_get_string(j_extraData);
				t_data = NULL;
				Base64Decode(t_b64Data, &t_data);
				if (!t_data) {
					printError("Base64 decode error", "");
					goto label_exit;
				}

				t_pointer1 = t_data;

				if (t_logEntryType == 1) {
					t_certSize = 0;
					memcpy(((char*)&t_certSize) + 1, t_pointer1, 3);
					t_certSize = be32toh(t_certSize);

					t_pointer1 += 3;
					t_pointer = t_pointer1;
					
					t_x509 = d2i_X509(
						NULL, (const unsigned char**)&t_pointer,
						t_certSize
					);
					if (!t_x509) {
						printError("Failed to decode Precertificate", t_b64Data);
						goto label_exit;
					}
					if (t_certSize != (t_pointer - t_pointer1)) {
						printError("Additional data after Precertificate", t_b64Data);
						t_certSize = t_pointer - t_pointer1;
					}

					t_subjectName = X509_NAME_oneline(
						X509_get_subject_name(t_x509), NULL, 0
					);
					printf("Precertificate: %s\n", t_subjectName);
					X509_free(t_x509);
					if (t_subjectName)
						OPENSSL_free(t_subjectName);

					/* Construct the "INSERT" query */
					sprintf(t_query[0],
						"SELECT import_ct_cert(%s::smallint, %d, %"
							LENGTH64 "u, E'\\\\x",
						PQgetvalue(t_PGresult_select, i, 0),
						(t_entryID + j), t_timestamp);

					for (k = 0; k < t_certSize; k++)
						sprintf(
							t_query[0] + strlen(t_query[0]), "%02X",
							*(unsigned char*)(t_pointer1 + k));
					strcat(t_query[0], "')");

					t_pointer1 = t_pointer;
				}

				/* Find the total length of the CA certificate array */
				t_totalLength = 0;
				memcpy(((char*)&t_totalLength) + 1, t_pointer1, 3);
				t_totalLength = be32toh(t_totalLength);
				t_pointer1 += 3;

				/* Parse each CA Certificate */
				while (t_totalLength > 0) {
					t_certSize = 0;
					memcpy(((char*)&t_certSize) + 1, t_pointer1, 3);
					t_certSize = be32toh(t_certSize);

					t_totalLength -= 3;
					t_pointer1 += 3;
					t_pointer = t_pointer1;
					
					t_x509 = d2i_X509(
						NULL, (const unsigned char**)&t_pointer,
						t_certSize
					);
					if (!t_x509) {
						printError("Failed to decode CA cert", t_b64Data);
						goto label_exit;
					}
					if (t_certSize != (t_pointer - t_pointer1)) {
						printError("Additional data after CA cert", t_b64Data);
						t_certSize = t_pointer - t_pointer1;
					}

					t_subjectName = X509_NAME_oneline(
						X509_get_subject_name(t_x509), NULL, 0
					);
					printf("CA: %s", t_subjectName);
					X509_free(t_x509);
					if (t_subjectName)
						OPENSSL_free(t_subjectName);

					/* Generate SHA-256(CACertificate) */
					EVP_DigestInit_ex(&t_mdctx, t_md, NULL);
					EVP_DigestUpdate(&t_mdctx, t_pointer1, t_certSize);
					EVP_DigestFinal_ex(&t_mdctx, t_sha256Hash_data, &t_sha256Hash_size);

					if ((!t_cachedCACerts) || (!bsearch(t_sha256Hash_data, t_cachedCACerts, t_nCachedCACerts, 32, compareSHA256Hashes))) {
						/* We've not cached this CA Certificate yet, so let's "INSERT" it and cache it */
						/* Construct the "INSERT" query */
						strcpy(t_query[t_nCertsInChain], "SELECT import_cert(E'\\\\x");
						for (k = 0; k < t_certSize; k++)
							sprintf(
								t_query[t_nCertsInChain] + strlen(t_query[t_nCertsInChain]), "%02X",
								*(unsigned char*)(t_pointer1 + k));
						strcat(t_query[t_nCertsInChain], "')");
						t_nCertsInChain++;

						/* Cache this SHA-256(CACertificate), then re-sort the list */
						t_nCachedCACerts++;
						t_cachedCACerts = realloc(t_cachedCACerts, t_nCachedCACerts * 32);
						(void)memcpy(t_cachedCACerts + ((t_nCachedCACerts - 1) * 32), t_sha256Hash_data, t_sha256Hash_size);
						qsort(t_cachedCACerts, t_nCachedCACerts, 32, compareSHA256Hashes);
					}
					else
						printf(" (Already cached)");

					printf("\n");

					t_totalLength -= (t_pointer - t_pointer1);
					t_pointer1 = t_pointer;
				}

				free(t_data);


			label_addCerts:
				/* Execute the "INSERT" quer(ies) */
				printf("Import %d cert%s: ", t_nCertsInChain, (t_nCertsInChain == 1) ? "" : "s");
				for (q = t_nCertsInChain - 1; q >= 0; q--) {
					t_PGresult = PQexec(t_PGconn, t_query[q]);
					if (PQresultStatus(t_PGresult) != PGRES_TUPLES_OK) {
						/* The SQL query failed */
						printError("Query failed", PQerrorMessage(t_PGconn));
						goto label_exit;
					}
					else if (PQgetisnull(t_PGresult, 0, 0)) {
						/* The SQL query failed */
						printError("Query failed", t_query[q]);
						goto label_exit;
					}

					PQclear(t_PGresult);
				}
				printf("OK\n");

				t_confirmedEntryID = t_entryID + j;

				if (g_terminateNow)
					goto label_exit;

				printf("\n");
			}

			if (json_object_put(j_getEntries) != 1) {
				printError(
					"json_object_put(j_getEntries)",
					"Did not return 1"
				);
				goto label_exit;
			}

			free(t_responseBuffer.data);
			t_responseBuffer.data = NULL;
			t_responseBuffer.size = 0;

			if (g_terminateNow)
				goto label_exit;
		}

		/* Cleanup the "easy handle" */
		curl_easy_cleanup(t_hEasy);
		t_hEasy = NULL;

		if (t_confirmedEntryID == -1)
			t_entryID--;
		else
			t_entryID = t_confirmedEntryID;
	}

	t_returnCode = EXIT_SUCCESS;

label_exit:
	printError("Terminated", NULL);

	/* Clear the query results */
	if (t_PGresult_select)
		PQclear(t_PGresult_select);

	/* Close this DB connection */
	if (t_PGconn)
		PQfinish(t_PGconn);

	/* Free the Response Buffer */
	if (t_responseBuffer.data)
		free(t_responseBuffer.data);

	/* Cleanup the "easy handle" */
	if (t_hEasy)
		curl_easy_cleanup(t_hEasy);

	/* curl_global_cleanup() must be called EXACTLY once */
	curl_global_cleanup();

	for (q = 0; q < 32; q++)
		if (t_query[q])
			free(t_query[q]);

	if (t_cachedCACerts)
		free(t_cachedCACerts);

	EVP_MD_CTX_cleanup(&t_mdctx);

	return t_returnCode;
}
