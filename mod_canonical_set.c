/*
=encoding utf8

=head1 NAME
 
mod_canonical_set.c -- Apache mod_canonical_set module

=head1 SYNOPSIS

 installation:
    apxs2 -i -c mod_canonical_set.c

 usage: add to httpd.conf
 
 LoadModule canonical_set_module modules/mod_canonical_set.so
 AddOutputFilterByType CANONICAL_SET text/html
 <Location "/">
     SeedForTranslation AAAAAAA
     HeaderEncryption ENC_URL
 </Location>
 <Location "/app1/">
     SeedForTranslation 1234567890
     HeaderEncryption ENC_URL
 </Location>
 <Location "/app2/">
     SeedForTranslation BLABLA
     HeaderEncryption GRIGRI
 </Location>


=head1 AUTHOR

Maurizio Abba'

=head1 LICENSE

Copyright 2013 Maurizio Abba'

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

=cut
*/

/*
TODO: 
    SEO friendly: if we find a canonical link inside a webpage, instead of encrypting the url encrypt the thing we find inside the href of the canonical link
*/

#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"
#include "ap_config.h"
#include "ap_regex.h"
#include "http_log.h"
#include "apr_strmatch.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "ap_provider.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"


#define VERSION "0.2"

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration structure
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

typedef struct {
    char *seed;
    char * dir;
    const char * header_encryption;
    unsigned int dir_len;
    unsigned int seed_len;
    unsigned int header_encryption_len;
    const apr_strmatch_pattern *pattern_encryption_start_tag;
    const apr_strmatch_pattern *dir_pattern;
} canonical_set_filter_config;

typedef struct {
    apr_bucket_brigade *bbsave;
} canonical_set_filter_ctx;

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Prototypes
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

static const char *canonical_set_filter_name = "CANONICAL_SET";
static const char *head_start_tag = "<head>";
static const unsigned int head_start_tag_length = 6;
static const char * link_can_tag = "<link rel=\"canonical\" href=";
static const char * link_end_tag = ">";
static const unsigned int link_end_tag_len=1;
static const char * replace_base = "<head><link rel=\"canonical\" href=\"%s%s%s\" />";

static const char * question_mark_tag = "?";
//static const char * header_encryption = "ENC_URL";
//static const unsigned int header_encryption_len = 8;
static const apr_strmatch_pattern *pattern_head_start_tag;
static const apr_strmatch_pattern *pattern_link_can_tag;
static const apr_strmatch_pattern *pattern_link_end_tag;
static const apr_strmatch_pattern *pattern_question_mark_tag;
static char * encrypt_path(apr_pool_t *p,const char *pass, unsigned int len_pass, const char * path);
static char * decrypt_path(apr_pool_t *p,const char *pass, unsigned int len_pass, const char * path);
static int decrypt_handler(request_rec *r);
static int canonical_set_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static apr_status_t canonical_set_out_filter(ap_filter_t *f, apr_bucket_brigade *bb);

void * create_dir_config(apr_pool_t *p, char *dir);
void * merge_dir_config(apr_pool_t *p, void *basev, void *overridesv);
static void register_hooks(apr_pool_t *p);
const char * set_header_encryption (cmd_parms *cmd, void *mconfig, const char *arg);
const char * set_seed(cmd_parms *cmd, void *mconfig, const char *arg);

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Configuration directives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

//TODO: check meaning of OR_FILEINFO
static const command_rec cmds[] = {
    AP_INIT_TAKE1("SeedForTranslation", set_seed, NULL, ACCESS_CONF, "Set the seed for url translation"),
    AP_INIT_TAKE1("HeaderEncryption", set_header_encryption, NULL, ACCESS_CONF, "Set the header for what it will be put in the url to identify encrypted urls"),
    {NULL}
};

/*$1
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    Our name tag
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

module AP_MODULE_DECLARE_DATA canonical_set_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,     /* create per-dir    config structures */
    merge_dir_config,      /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    cmds,                  /* table of config file commands       */
    register_hooks         /* register hooks */
};


/*
 =======================================================================================================================
    Hook registration function
 =======================================================================================================================
 */


static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(canonical_set_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_output_filter(canonical_set_filter_name, canonical_set_out_filter, NULL, AP_FTYPE_RESOURCE);
//    ap_hook_post_read_request(decrypt_handler, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_translate_name(decrypt_handler, NULL, NULL, APR_HOOK_FIRST);
//    ap_hook_handler(decrypt_handler, NULL, NULL, APR_HOOK_MIDDLE);

}

/*
 =======================================================================================================================
    Filter function
 =======================================================================================================================
 */


static apr_status_t canonical_set_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    canonical_set_filter_ctx *ctx = f->ctx;
    canonical_set_filter_config *c;

    apr_bucket *b = APR_BRIGADE_FIRST(bb);

    apr_size_t bytes, bytes2;
    apr_size_t fbytes;
    apr_size_t offs;
    const char *buf;
    const char *le = NULL;
    const char *le_n;
    const char *le_r;

    const char *bufp;
    const char *subs;
    unsigned int match;

    apr_bucket *b1;
    apr_bucket *b2;

    char * path_uri;
    const char * complete_uri;
    const char * enc_uri;
    const char * rep;
    char *fbuf;
    int found = 0;
    apr_status_t rv;

    const char * tfilename;
    const char * exists;
    int len_path;


    apr_bucket_brigade *bbline;

    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }
    
    if (r->main) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    
    c = ap_get_module_config(r->per_dir_config, &canonical_set_module);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: initial uri: %s", r->uri);
    tfilename=r->uri;
    len_path = strlen(tfilename);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: tfilename set to %s", tfilename);
    exists = apr_strmatch(c->pattern_encryption_start_tag, tfilename, len_path);
    if (exists || apr_strnatcmp(tfilename,"/")==0 ) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: requested / or uri already ENC_URI, leaving");
        return APR_SUCCESS;
    }


    if (ctx == NULL) {
        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(canonical_set_filter_ctx));
        ctx->bbsave = apr_brigade_create(r->pool, f->c->bucket_alloc);
    }

    apr_table_unset(r->headers_out, "Content-Length");
    apr_table_unset(r->headers_out, "Content-MD5");
    apr_table_unset(r->headers_out, "Accept-Ranges");
    apr_table_unset(r->headers_out, "ETag");

    /*STEP 1: according to https://httpd.apache.org/docs/trunk/developer/output-filters.html
             we create a temporary brigade in order to consume a fixed amount of memory instead of consume menory proportionally to content size
            in the mean time we split the buckets at each new line*/
    bbline = apr_brigade_create(r->pool, f->c->bucket_alloc); 
    while ( b != APR_BRIGADE_SENTINEL(bb) ) {
        if ( !APR_BUCKET_IS_METADATA(b) ) {
            if ( apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS ) {
                if ( bytes == 0 ) {
                    APR_BUCKET_REMOVE(b);
                } 
                else {
					while ( bytes > 0 ) {
						le_n = memchr(buf, '\n', bytes);
                        le_r = memchr(buf, '\r', bytes);
                        if ( le_n != NULL ) {
                            if ( le_n == le_r + sizeof(char)) {le = le_n;}
                            else if ( (le_r < le_n) && (le_r != NULL) ) {le = le_r;}
                            else {le = le_n;}
                        }
                        else {le = le_r;}
                        if ( le ) {
                            offs = 1 + ((unsigned int)le-(unsigned int)buf) / sizeof(char);
                            apr_bucket_split(b, offs);
                            bytes -= offs;
                            buf += offs;
                            b1 = APR_BUCKET_NEXT(b);
                            APR_BUCKET_REMOVE(b);
                            if ( !APR_BRIGADE_EMPTY(ctx->bbsave) ) {
                                APR_BRIGADE_INSERT_TAIL(ctx->bbsave, b);
                                rv = apr_brigade_pflatten(ctx->bbsave, &fbuf, &fbytes, r->pool);
                                b = apr_bucket_pool_create(fbuf, fbytes, r->pool,r->connection->bucket_alloc);
                                apr_brigade_cleanup(ctx->bbsave);
                            }
                            APR_BRIGADE_INSERT_TAIL(bbline, b);
                            b = b1;
                        } else {
                            APR_BUCKET_REMOVE(b);
                            APR_BRIGADE_INSERT_TAIL(ctx->bbsave, b);
                            bytes = 0;
                        }
                    } // while bytes > 0 
				}
            } 
            else {
                APR_BUCKET_REMOVE(b);
            }
        } 
        else if ( APR_BUCKET_IS_EOS(b) ) {
            if ( !APR_BRIGADE_EMPTY(ctx->bbsave) ) {
                rv = apr_brigade_pflatten(ctx->bbsave, &fbuf, &fbytes, r->pool);
                b1 = apr_bucket_pool_create(fbuf, fbytes, r->pool,
                                            r->connection->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bbline, b1);
            }
            apr_brigade_cleanup(ctx->bbsave);
            f->ctx = NULL;
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(bbline, b);
        } 
        else {
            apr_bucket_delete(b);
        }
        b = APR_BRIGADE_FIRST(bb);
    }

    /*STEP 2: here we apply our filter on the obtained temp brigade.
            2 operations:
                - remove any other <link rel canonical blabla thing (if more than one SEO will discard all of them)
                - insert our encrypted tag */
    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server,"ENCRYPT: begin step 2");
    for ( b = APR_BRIGADE_FIRST(bbline);
          b != APR_BRIGADE_SENTINEL(bbline);
          b = APR_BUCKET_NEXT(b) ) {
        if ( !APR_BUCKET_IS_METADATA(b)
             && (apr_bucket_read(b, &buf, &bytes, APR_BLOCK_READ) == APR_SUCCESS)) {
                //THIS PART IS NEEDED FOR REMOVING ANY OTHER LINK CANONICAL
                bufp=buf;
                subs = apr_strmatch(pattern_link_can_tag, bufp, bytes); //look for a <link rel="canonical"..
                if (subs!= NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: found link canonical tag");
                    match = ((unsigned int)subs - (unsigned int)bufp) / sizeof(char);
                    apr_bucket_split(b, match); //split at the beginning of <link
                    b1=APR_BUCKET_NEXT(b);
                    if (apr_bucket_read(b1, &bufp, &bytes2, APR_BLOCK_READ)== APR_SUCCESS) { //read next bucket in order to remove the whole tag
                        subs = apr_strmatch(pattern_link_end_tag, bufp, bytes2);
                        if (subs!=NULL) {
                            match = ((unsigned int)subs - (unsigned int)bufp) / sizeof(char)+link_end_tag_len; //include in the thing removal of >
                            apr_bucket_split(b1, match); //split at the end >
                            apr_bucket_delete(b1); //delete the entire bucket <link .... >
                        }
                        else {/*EPIC FAIL*/ 
                            ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: link end tag not found, HTML is broken?");
                        }
                    }
                    else {/*EPIC FAIL*/
                        ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: Failure in reading bucket");
                    }
                }
                bufp = buf;
                subs = apr_strmatch(pattern_head_start_tag, bufp, bytes);
                if (subs != NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: found head tag");
                    match = ((unsigned int)subs - (unsigned int)bufp) / sizeof(char); 
                    bytes -= match;
                    bufp += match;
                    apr_bucket_split(b, match); //split bucket in first part and part at <head
                    b1 = APR_BUCKET_NEXT(b); //get from <head after
                    apr_bucket_split(b1, head_start_tag_length); //split in two buckets: "<head>" and everything after
                    b2 = APR_BUCKET_NEXT(b1); //get everything after
                    apr_bucket_delete(b1); //remove "<head>"
                    bytes -= head_start_tag_length;
                    bufp += head_start_tag_length;

                    //take the path part of the uri
                    path_uri = apr_strmatch(c->dir_pattern, r->uri, strlen(r->uri));
                    path_uri += c->dir_len;
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: path_uri %s", path_uri);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: args %s", r->args);

                    //build the uri as <path>?<args> if there's args, otherwise just <path> 
                    complete_uri = (r->args!=NULL) ?  apr_psprintf(r->pool, "%s?%s", path_uri, r->args) :  apr_psprintf(r->pool, "%s", path_uri);

                    enc_uri = encrypt_path(r->pool, c->seed, c->seed_len, complete_uri);
                    rep = apr_psprintf(r->pool, replace_base, c->dir,c->header_encryption, enc_uri);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: will add on page %s", rep);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: composed by c->dir %s", c->dir);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: composed by header_encryption %s", c->header_encryption);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: composed by enc_uri %s", enc_uri);
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: unparsed_uri is %s", r->unparsed_uri);
                    b1 = apr_bucket_immortal_create(rep, strlen(rep),r->connection->bucket_alloc);
                    APR_BUCKET_INSERT_BEFORE(b2, b1); //put b1 before b2
                    b=b2;
                }
        }
    }

    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "ENCRYPT: filter ended");

    rv = ap_pass_brigade(f->next, bbline);

    for ( b = APR_BRIGADE_FIRST(ctx->bbsave);
          b != APR_BRIGADE_SENTINEL(ctx->bbsave);
          b = APR_BUCKET_NEXT(b)) {
        apr_bucket_setaside(b, r->pool);
    }

    return rv;
}

/*
 =======================================================================================================================
    Encrypt and Decrypt string function
 =======================================================================================================================
 */

static char * encrypt_path(apr_pool_t *p,const char *pass, unsigned int len_pass, const char * path) 
{
    char * result;
    char * tres;
    int len_path;
    int cnt;
 
    len_path = strlen(path);
    result = (char *) apr_pcalloc(p, ((len_path*2+1)*sizeof(char)));
    tres=result;
    for (cnt=0; cnt < len_path; cnt++) {
        sprintf(tres,"%02x", path[cnt]^pass[cnt%len_pass]);
        tres+=2;
    }
    result[(len_path*2)]='\0'; 
    return result;
}

static char * decrypt_path(apr_pool_t *p, const char *pass, unsigned int len_pass,  const char * path) 
{
  char * result;
  char * tres;
  char * tpath;
  unsigned int cnt;
  unsigned int tlett;
  unsigned int len_path;

  len_path = strlen(path);
  if (len_path%2!= 0)
    return NULL;
  result = (char *) apr_pcalloc(p,((len_path/2)+1)*sizeof(char));
  tres=result;
  tpath = path;
  for (cnt=0; cnt < len_path/2; cnt++) {
    sscanf(tpath, "%2x", &tlett);
    sprintf(tres,"%c", tlett^pass[cnt%len_pass]);
    tres+=1;
    tpath+=2;
  }
  result[(len_path/2)]='\0';
  return result;
}

/*
 =======================================================================================================================
    Handler function
 =======================================================================================================================
 */

static int decrypt_handler(request_rec *r) 
{
    const char *subs;
    char * enc_url;
    char * tfilename;
    canonical_set_filter_config * c = (canonical_set_filter_config *) ap_get_module_config(r->per_dir_config, &canonical_set_module);
    unsigned int len_path;
    char * rpath;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: initial uri: %s", r->uri);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: initial args: %s", r->args);
    

    if (r->uri[0]=='*' && r->uri[1]=='\0') {
      ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: asked for *, leave it");
        return DECLINED;
    }

    tfilename = apr_pstrdup(r->pool, r->uri+c->dir_len);
    //if the request is just the /, don't do anything 
    if (apr_strnatcmp(tfilename, "/")!=0) {
        len_path = strlen(tfilename);
        if (tfilename[len_path-1]=='/') {
            tfilename[len_path-1]='\0';
            len_path-=1;
        }
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: tfilename set to %s", tfilename);
        //look for ENC_URL path
        subs = apr_strmatch(c->pattern_encryption_start_tag, tfilename, len_path);        
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: subs value:  %s", subs);
        if (subs != NULL) {
            //we found an ENC_URL, hurray!!
            enc_url = apr_pstrdup(r->pool,tfilename+c->header_encryption_len);
            rpath = decrypt_path(r->pool, c->seed, c->seed_len ,enc_url);
            r->uri = apr_pstrcat(r->pool, c->dir,rpath,NULL);
            subs = apr_strmatch (pattern_question_mark_tag, rpath, strlen(rpath));
            if (subs != NULL) { //WE HAVE SOME ARGS other than the url
                r->args = apr_pstrdup(r->pool, subs+sizeof(char)); //remove ?
                r->uri[subs-rpath+sizeof(char)]='\0';
                } 
           ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: new uri:  %s", r->uri);
           ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: new args:  %s", r->args);
            //we changed the url, return gracefully
            return DECLINED;
        }
        else {
            //if path does not have the ENC_URL tag, decline so that it can go wherever it wants
            ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: subs is null, tfilename not set");
            return DECLINED;
        }
    }
    else {
        //asked for /, we decline the request so that it can be supported by somebody else
        ap_log_error(APLOG_MARK, APLOG_ERR, 0,r->server, "DECRYPT: asked for /, leave it");
        return DECLINED;
    }
    //here should be impossible to go, anyway if we are here we for sure don't want to do anything
    return DECLINED;
}

void * create_dir_config(apr_pool_t *p, char *dir)
{
    canonical_set_filter_config *c = apr_pcalloc(p, sizeof(canonical_set_filter_config));
    if (dir == NULL) {
        c->dir = apr_pstrdup(p, "/");
    }
   else {
        /* make sure it has a trailing slash */
        if (dir[strlen(dir)-1] == '/') {
            c->dir = apr_pstrdup(p, dir);
        }
        else {
            c->dir = apr_pstrcat(p, dir, "/", NULL);
        }
    }
    c->dir_len = strlen(c->dir);
    c->dir_pattern = apr_strmatch_precompile(p, c->dir, 0);
    c->seed = NULL;
    c->seed_len =0;
    c->header_encryption = NULL;
    c->header_encryption_len =0;

    return (void *) c;
}

void * merge_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    canonical_set_filter_config *c = (canonical_set_filter_config *) apr_palloc(p, sizeof(canonical_set_filter_config));
    canonical_set_filter_config *base = (canonical_set_filter_config *)basev;
    canonical_set_filter_config *overrides = (canonical_set_filter_config *)overridesv;
    c->seed = overrides->seed ? overrides->seed : base->seed;
    c->seed_len = overrides->seed_len ? overrides->seed_len : base->seed_len;
    c->dir = overrides->dir ? overrides->dir : base->dir;
    c->dir_len = overrides->dir_len ? overrides->dir_len : base->dir_len;
    c->dir_pattern = overrides->dir_pattern ? overrides->dir_pattern : base->dir_pattern;
    c->header_encryption = overrides->header_encryption ? overrides->header_encryption : base->header_encryption;
    c->header_encryption_len = overrides->header_encryption_len ? overrides->header_encryption_len : base->header_encryption_len;
    c->pattern_encryption_start_tag = overrides->pattern_encryption_start_tag ? overrides->pattern_encryption_start_tag : base->pattern_encryption_start_tag;
    
   return (void *) c;
}

const char * set_seed(cmd_parms *cmd, void *mconfig, const char *arg)
{
    canonical_set_filter_config *c = (canonical_set_filter_config *)mconfig;
    // TODO check seed that is a string 
    if (arg!=NULL) {
        c->seed = apr_pstrdup(cmd->pool, arg);
    }
    else {
        c->seed = apr_pstrdup(cmd->pool, "AAAA");
    }
    c->seed_len = strlen(c->seed);
    return NULL;
}

const char * set_header_encryption (cmd_parms *cmd, void *mconfig, const char *arg)
{
    canonical_set_filter_config *c = (canonical_set_filter_config *)mconfig;
    // TODO check seed that is a string 
    if (arg!= NULL) {
        c->header_encryption = apr_pstrdup(cmd->pool, arg);
    }
    else {
        c->header_encryption = apr_pstrdup(cmd->pool, "BBBBB");
    }
    c->header_encryption_len = strlen(c->header_encryption);
    c->pattern_encryption_start_tag = apr_strmatch_precompile(cmd->pool, c->header_encryption, 0);
    return NULL;
}


static int canonical_set_post_config(apr_pool_t *p, apr_pool_t *plog,
										apr_pool_t *ptemp, server_rec *s)
{
	pattern_head_start_tag = apr_strmatch_precompile(p, head_start_tag, 0);
	pattern_link_can_tag = apr_strmatch_precompile(p, link_can_tag, 0);
	pattern_link_end_tag = apr_strmatch_precompile(p, link_end_tag, 0);
    pattern_question_mark_tag = apr_strmatch_precompile(p, question_mark_tag, 0);
	return OK;
}


