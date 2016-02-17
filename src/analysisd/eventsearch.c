/* @(#) $Id: ./src/analysisd/eventsearch.c, 2016/01/10 dcid Exp $
 */

/* Copyright (C) 2016 Daniel B. Cid
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 */



#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"



/* Unified Search function to look up the last events. */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    OSListNode *lf_node;


    /* Setting frequency to 0 */
    currently_rule->__frequency = 0;


    /* Getting last node */
    if(currently_rule->sid_search)
    {
        lf_node = OSList_GetLastNode(currently_rule->sid_search);
    }
    else if(currently_rule->group_search)
    {
        lf_node = OSList_GetLastNode(currently_rule->group_search);
    }


    /* Getting last node */
    if(!lf_node)
    {
        return(NULL);
    }
    first_lf = (Eventinfo *)lf_node->data;


    do
    {
        lf = (Eventinfo *)lf_node->data;

        /* If time is outside the timeframe, return */
        if((c_time - lf->time) > currently_rule->timeframe)
        {
            return(NULL);
        }


        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if(lf->matched >= currently_rule->level)
        {
            return(NULL);
        }



        /* Checking for same id */
        if(currently_rule->context_opts & SAME_ID)
        {
            if((!lf->id) || (!my_lf->id))
                continue;

            if(strcmp(lf->id,my_lf->id) != 0)
                continue;
        }

        /* Checking for repetitions from same src_ip */
        if(currently_rule->context_opts & SAME_SRCIP)
        {
            if((!lf->srcip)||(!my_lf->srcip))
                continue;

            if(strcmp(lf->srcip,my_lf->srcip) != 0)
                continue;
        }


        /* Grouping of additional data */
        if(currently_rule->alert_opts & SAME_EXTRAINFO)
        {
            /* Checking for same source port */
            if(currently_rule->context_opts & SAME_SRCPORT)
            {
                if((!lf->srcport)||(!my_lf->srcport))
                    continue;

                if(strcmp(lf->srcport, my_lf->srcport) != 0)
                    continue;
            }

            /* Checking for same dst port */
            if(currently_rule->context_opts & SAME_DSTPORT)
            {
                if((!lf->dstport)||(!my_lf->dstport))
                    continue;

                if(strcmp(lf->dstport, my_lf->dstport) != 0)
                    continue;
            }

            /* Checking for repetitions on user error */
            if(currently_rule->context_opts & SAME_USER)
            {
                if((!lf->dstuser)||(!my_lf->dstuser))
                    continue;

                if(strcmp(lf->dstuser,my_lf->dstuser) != 0)
                    continue;
            }

            /* Checking for same location */
            if(currently_rule->context_opts & SAME_LOCATION)
            {
                if(strcmp(lf->hostname, my_lf->hostname) != 0)
                    continue;
            }


            /* Checking for different urls */
            if(currently_rule->context_opts & DIFFERENT_URL)
            {
                short int hashopr;
                if((!lf->url)||(!my_lf->url))
                {
                    continue;
                }

                if(strcmp(lf->url, my_lf->url) == 0)
                {
                    continue;
                }

                /* Create hash to store and compare for differences. */
                if(currently_rule->event_hash == NULL)
                {
                    currently_rule->event_hash = OSHash_Create();
                }
                hashopr = OSHash_Add(currently_rule->event_hash, lf->url, lf->url);
                /* Duplicated key / error, not different as already in the hash. */
                if(hashopr == 1 || hashopr == 0)
                {
                    continue;
                }
            }


            /* Checking for different srcip */
            if(currently_rule->context_opts & DIFFERENT_SRCIP)
            {
                short int hashopr;
                if((!lf->srcip)||(!my_lf->srcip))
                {
                    continue;
                }

                if(strcmp(lf->srcip, my_lf->srcip) == 0)
                {
                    continue;
                }

                /* Create hash to store and compare for differences. */
                if(currently_rule->event_hash == NULL)
                {
                    currently_rule->event_hash = OSHash_Create();
                }
                hashopr = OSHash_Add(currently_rule->event_hash, lf->srcip, lf->srcip);
                /* Duplicated key / error, not different as already in the hash. */
                if(hashopr == 1 || hashopr == 0)
                {
                    continue;
                }
            }

            /* Checking for different srcgeoip */
            if(currently_rule->context_opts & DIFFERENT_GEOIP)
            {
                short int hashopr;
                if((!lf->srcgeoip)||(!my_lf->srcgeoip))
                {
                    continue;
                }

                if(strcmp(lf->srcgeoip, my_lf->srcgeoip) == 0)
                {
                    continue;
                }

                /* Create hash to store and compare for differences. */
                if(currently_rule->event_hash == NULL)
                {
                    currently_rule->event_hash = OSHash_Create();
                }
                hashopr = OSHash_Add(currently_rule->event_hash, lf->srcgeoip, lf->srcgeoip);
                /* Duplicated key / error, not different as already in the hash. */
                if(hashopr == 1 || hashopr == 0)
                {
                    continue;
                }
            }


        }


        /* Adding last entries to the last_events array so we can display them
         * in the alert. */
        if(currently_rule->__frequency <= 10)
        {
            currently_rule->last_events[currently_rule->__frequency]
                = lf->full_log;
            currently_rule->last_events[currently_rule->__frequency+1]
                = NULL;
        }


        /* Checking if the number of matches worked */
        if(currently_rule->__frequency < currently_rule->frequency)
        {
            currently_rule->__frequency++;
            continue;
        }


        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
        lf->matched = currently_rule->level;
        first_lf->matched = currently_rule->level;

        return(lf);


    }while((lf_node = lf_node->prev) != NULL);

    return(NULL);
}




/* EOF */
