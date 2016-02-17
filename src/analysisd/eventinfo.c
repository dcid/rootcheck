/* @(#) $Id: ./src/analysisd/eventinfo.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
 */




#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"




/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    lf->log = NULL;
    lf->full_log = NULL;
    lf->hostname = NULL;
    lf->program_name = NULL;
    lf->location = NULL;

    lf->srcip = NULL;
    lf->srcgeoip = NULL;
    lf->dstip = NULL;
    lf->dstgeoip = NULL;
    lf->srcport = NULL;
    lf->dstport = NULL;
    lf->protocol = NULL;
    lf->action = NULL;
    lf->srcuser = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->status = NULL;
    lf->command = NULL;
    lf->url = NULL;
    lf->data = NULL;
    lf->systemname = NULL;

    lf->time = 0;
    lf->matched = 0;
    
    lf->year = 0;
    lf->mon[3] = '\0';
    lf->hour[9] = '\0';
    lf->day = 0;

    lf->generated_rule = NULL;
    lf->sid_node_to_delete = NULL;
    lf->decoder_info = NULL_Decoder;

    #ifdef PRELUDE
    lf->filename = NULL;
    lf->perm_before = 0;      
    lf->perm_after = 0;          
    lf->md5_before = NULL;                 
    lf->md5_after = NULL;               
    lf->sha1_before = NULL;       
    lf->sha1_after = NULL;                 
    lf->size_before = NULL;       
    lf->size_after = NULL;        
    lf->owner_before = NULL;      
    lf->owner_after = NULL;       
    lf->gowner_before = NULL; 
    lf->gowner_after = NULL;  
    #endif

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if(!lf)
    {
        merror("%s: Trying to free NULL event. Inconsistent..",ARGV0);
        return;
    }
    
    if(lf->full_log)
        free(lf->full_log);    
    if(lf->location)
        free(lf->location);    

    if(lf->srcip)
        free(lf->srcip);
    if(lf->srcgeoip)
    {
        free(lf->srcgeoip);
        lf->srcgeoip = NULL;
    }
    if(lf->dstip)
        free(lf->dstip);
    if(lf->dstgeoip)
    {
        free(lf->dstgeoip);
        lf->dstgeoip = NULL;
    }
    if(lf->srcport)
        free(lf->srcport);
    if(lf->dstport)
        free(lf->dstport);
    if(lf->protocol)
        free(lf->protocol);
    if(lf->action)
        free(lf->action);            
    if(lf->status)
        free(lf->status);
    if(lf->srcuser)
        free(lf->srcuser);
    if(lf->dstuser)
        free(lf->dstuser);    
    if(lf->id)
        free(lf->id);
    if(lf->command)
        free(lf->command);
    if(lf->url)
        free(lf->url);

    if(lf->data)
        free(lf->data);    
    if(lf->systemname)
        free(lf->systemname);    

    #ifdef PRELUDE
    if(lf->filename)
        free(lf->filename);
    if (lf->md5_before)
        free(lf->md5_before);                 
    if (lf->md5_after)
        free(lf->md5_after);               
    if (lf->sha1_before)
        free(lf->sha1_before);       
    if (lf->sha1_after)
        free(lf->sha1_after);                 
    if (lf->size_before)
        free(lf->size_before);       
    if (lf->size_after)
        free(lf->size_after);        
    if (lf->owner_before)
        free(lf->owner_before);      
    if (lf->owner_after)
        free(lf->owner_after);       
    if (lf->gowner_before)
        free(lf->gowner_before); 
    if (lf->gowner_after)
        free(lf->gowner_after);  
    #endif

    /* Freeing node to delete */
    if(lf->sid_node_to_delete)
    {
        OSList_DeleteThisNode(lf->generated_rule->sid_prev_matched, 
                              lf->sid_node_to_delete);
    }
    else if(lf->generated_rule && lf->generated_rule->group_prev_matched)
    {
        int i = 0;

        while(i < lf->generated_rule->group_prev_matched_sz)
        {
            OSList_DeleteOldestNode(lf->generated_rule->group_prev_matched[i]);
            i++;
        } 
    }
    
    /* We dont need to free:
     * fts
     * comment
     */
    free(lf);
    lf = NULL; 
    
    return;
}	

/* EOF */
