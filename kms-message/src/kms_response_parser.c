#include "kms_message/kms_response_parser.h"
#include "kms_message_private.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

/* destroys the members of parser, but not the parser itself. */
static void
_parser_destroy (kms_response_parser_t *parser)
{
   kms_request_str_destroy (parser->raw_response);
   parser->raw_response = NULL;
   parser->content_length = -1;
   kms_response_destroy (parser->response);
   parser->response = NULL;
}

/* initializes the members of parser. */
static void
_parser_init (kms_response_parser_t *parser)
{
   parser->raw_response = kms_request_str_new ();
   parser->content_length = -1;
   parser->response = calloc (1, sizeof (kms_response_t));
   parser->response->headers = kms_kv_list_new ();
   parser->state = PARSING_STATUS_LINE;
   parser->start = 0;
   parser->failed = false;
}

kms_response_parser_t *
kms_response_parser_new (void)
{
   kms_response_parser_t *parser = malloc (sizeof (kms_response_parser_t));
   _parser_init (parser);
   return parser;
}

int
kms_response_parser_wants_bytes (kms_response_parser_t *parser, int32_t max)
{
   switch (parser->state) {
   case PARSING_DONE:
      return 0;
   case PARSING_STATUS_LINE:
   case PARSING_HEADER:
      return max;
   case PARSING_BODY:
      assert (parser->content_length != -1);
      return parser->content_length -
             ((int) parser->raw_response->len - parser->start);
   }
   return -1;
}

static bool
_parse_int (const char *str, int *result)
{
   char *endptr = NULL;

   *result = (int) strtol (str, &endptr, 10);
   if (*endptr) {
      return false;
   }
   return true;
}

/* parse an int from a substring inside of a string. */
static bool
_parse_int_from_view (const char *str, int start, int end, int *result)
{
   char *num_str = malloc (end - start + 1);
   bool ret;

   strncpy (num_str, str + start, end - start);
   num_str[end - start] = '\0';
   ret = _parse_int (num_str, result);
   free (num_str);
   return ret;
}

/* returns true if char is "linear white space". This *ignores* the folding case
 * of CRLF followed by WSP. See https://stackoverflow.com/a/21072806/774658 */
static bool
_is_lwsp (char c)
{
   return c == ' ' || c == 0x09 /* HTAB */;
}

/* parse a header line or status line. */
static kms_response_parser_state_t
_parse_line (kms_response_parser_t *parser, int end)
{
   int i = parser->start;
   const char *raw = parser->raw_response->str;
   kms_response_t *response = parser->response;

   if (parser->state == PARSING_STATUS_LINE) {
      /* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF */
      int j;
      int status;

      if (strncmp (raw + i, "HTTP/1.1 ", 9) != 0) {
         KMS_ERROR (parser, "Could not parse HTTP-Version.");
         return PARSING_DONE;
      }
      i += 9;

      for (j = i; j < end; j++) {
         if (raw[j] == ' ')
            break;
      }

      if (!_parse_int_from_view (raw, i, j, &status)) {
         KMS_ERROR (parser, "Could not parse Status-Code.");
         return PARSING_DONE;
      }

      response->status = status;

      /* Error for non-ok statuses. */
      if (response->status != 200) {
         KMS_ERROR (parser, "Parsed a non-ok Status-Code.");
         return PARSING_DONE;
      }

      /* ignore the Reason-Phrase. */
      return PARSING_HEADER;
   } else if (parser->state == PARSING_HEADER) {
      /* Treating a header as:
       * message-header = field-name ":" [ field-value ] CRLF
       * This is not completely correct, and does not take folding into acct.
       * See https://tools.ietf.org/html/rfc822#section-3.1
       */
      int j;
      kms_request_str_t *key;
      kms_request_str_t *val;

      if (i == end) {
         /* empty line, this signals the start of the body. */
         return PARSING_BODY;
      }

      for (j = i; j < end; j++) {
         if (raw[j] == ':')
            break;
      }

      if (j == end) {
         KMS_ERROR (parser, "Could not parse header, no colon found.");
         return PARSING_DONE;
      }

      key = kms_request_str_new_from_chars (raw + i, j - i);

      i = j + 1;
      /* remove leading and trailing whitespace from the value. */
      for (j = i; j < end; j++) {
         if (!_is_lwsp (raw[j]))
            break;
      }
      i = j;

      /* find the end of the header by backtracking. */
      for (j = end; j > i; j--) {
         if (!_is_lwsp (raw[j]))
            break;
      }

      if (i == j) {
         val = kms_request_str_new ();
      } else {
         val = kms_request_str_new_from_chars (raw + i, j - i);
      }

      kms_kv_list_add (response->headers, key, val);

      /* if we have *not* read the Content-Length yet, check. */
      if (parser->content_length == -1 &&
          strcmp (key->str, "Content-Length") == 0) {
         if (!_parse_int (val->str, &parser->content_length)) {
            KMS_ERROR (parser, "Could not parse Content-Length header.");
            kms_request_str_destroy (key);
            kms_request_str_destroy (val);
            return PARSING_DONE;
         }
      }
      kms_request_str_destroy (key);
      kms_request_str_destroy (val);
      return PARSING_HEADER;
   }
   return PARSING_DONE;
}

bool
kms_response_parser_feed (kms_response_parser_t *parser,
                          uint8_t *buf,
                          uint32_t len)
{
   kms_request_str_t *raw = parser->raw_response;
   int curr, body_read;

   curr = (int) raw->len;
   kms_request_str_append_chars (raw, (char *) buf, len);
   /* process the new data appended. */
   while (curr < (int) raw->len) {
      switch (parser->state) {
      case PARSING_STATUS_LINE:
      case PARSING_HEADER:
         /* find the next \r\n. */
         if (curr && strncmp (raw->str + (curr - 1), "\r\n", 2) == 0) {
            parser->state = _parse_line (parser, curr - 1);
            parser->start = curr + 1;
         }
         curr++;
         break;
      case PARSING_BODY:
         body_read = (int) raw->len - parser->start;

         if (parser->content_length == -1 ||
             body_read > parser->content_length) {
            KMS_ERROR (parser, "Could not parse content length.");
            return false;
         }

         /* check if we have the entire body. */
         if (body_read == parser->content_length) {
            parser->response->body = kms_request_str_new_from_chars (
               raw->str + parser->start, parser->content_length);
            parser->state = PARSING_DONE;
         }

         curr = (int) raw->len;
         break;
      case PARSING_DONE:
         if (parser->failed) {
            return false;
         }

         return true;
      }
   }

   if (parser->failed) {
      return false;
   }
   return true;
}

/* steals the response from the parser. */
kms_response_t *
kms_response_parser_get_response (kms_response_parser_t *parser)
{
   kms_response_t *response = parser->response;

   parser->response = NULL;
   /* reset the parser. */
   _parser_destroy (parser);
   _parser_init (parser);
   return response;
}

int
kms_response_parser_status (kms_response_parser_t *parser)
{
   if (!parser || !(parser->response)) {
      return 0;
   }

   return parser->response->status;
}

const char *
kms_response_parser_error (kms_response_parser_t *parser)
{
   if (!parser) {
      return NULL;
   }

   return parser->error;
}

void
kms_response_parser_destroy (kms_response_parser_t *parser)
{
   _parser_destroy (parser);
   free (parser);
}
